package disguise

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/observe"
)

var uaVersionRegex = regexp.MustCompile(`^claude-cli/(\d+\.\d+\.\d+)`)

// extractUAVersion extracts the version string from a Claude CLI User-Agent.
// Returns "" if the UA does not match the expected pattern.
func extractUAVersion(ua string) string {
	m := uaVersionRegex.FindStringSubmatch(ua)
	if m == nil {
		return ""
	}
	return m[1]
}

// Engine orchestrates the multi-layer Claude CLI impersonation.
type Engine struct {
	fingerprints *FingerprintStore
	sessions     *SessionMaskStore
	billingProbe *BillingHeaderObserver
}

// NewEngine creates a new disguise engine with per-account fingerprint storage
// and session masking. dataDir is the path to the persistent data directory.
func NewEngine(dataDir string) *Engine {
	return &Engine{
		fingerprints: NewFingerprintStore(dataDir),
		sessions:     NewSessionMaskStore(),
		billingProbe: NewBillingHeaderObserver(),
	}
}

// GetFingerprintStore returns the underlying fingerprint store (for migration).
func (e *Engine) GetFingerprintStore() *FingerprintStore {
	return e.fingerprints
}

// StartSessionCleanup begins periodic cleanup of expired masked sessions.
func (e *Engine) StartSessionCleanup(ctx context.Context) {
	e.sessions.StartCleanup(ctx, time.Minute)
}

// Apply modifies the request and body for Claude CLI impersonation.
// Returns the (possibly modified) body and whether disguise was applied.
//
// origReq is the original incoming request (used for Claude Code client detection
// because it has the full set of headers: User-Agent, X-App, etc.).
// upstreamReq is the outbound request to Anthropic (headers/body are modified here).
// accountName identifies which proxy account is being used (for per-account fingerprinting).
//
// The layers:
// 1. TLS fingerprint — handled externally by HTTP transport selection
// 2. HTTP headers — User-Agent, X-Stainless-*, etc. (per-account fingerprint)
// 3. anthropic-beta — scenario-based beta token composition
// 4. System prompt injection — inject Claude Code system prompt
// 5. metadata.user_id — generate/rewrite fake user_id with session masking
// 6. Model ID normalization — short name → full versioned name
// 7. Thinking cache_control cleanup — remove cache_control from thinking blocks
// 8. Body sanitization — tools injection, field removal
func (e *Engine) Apply(origReq *http.Request, upstreamReq *http.Request, body []byte, isStream bool, sessionSeed string, accountID string, accountName string) ([]byte, bool) {
	ctx := origReq.Context()

	// Detect using origReq which has full client headers (User-Agent, X-App, etc.)
	if IsClaudeCodeClient(origReq.Header, body, origReq.URL.Path) {
		observe.Logger(ctx).Debug("disguise: native Claude Code client detected, lightweight pass-through",
			"account", accountName,
		)
		// Learn fingerprint from real CC client for future disguise use
		e.fingerprints.LearnFromHeaders(accountID, origReq.Header)
		// Get per-account fingerprint (ensures ClientID is initialized for this account).
		fp := e.fingerprints.Get(accountID)

		// Real CC client via OAuth: lightweight processing only.
		// 1. Parse body first — filtering and user_id rewriting both require parsed state.
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return body, true
		}

		// 2. Unify HTTP headers to the account's fingerprint so every user of
		//    this account looks like a single stable CLI install to Anthropic.
		//    This overrides the client's User-Agent and X-Stainless-* values
		//    with fp.UserAgent / fp.StainlessPackageVersion / etc. Without this,
		//    different client machines would leak their real versions via the
		//    pass-through headers, making cross-user correlation trivial.
		ApplyHeaders(upstreamReq, isStream, fp)

		// 3. Build canonical anthropic-beta from the 2.1.88 baseline, preserving
		//    client extras. CC path must use the SAME canonical set as the
		//    non-CC path because we also override UA to the fingerprint UA
		//    (2.1.88) — if the beta set still reflected the client's old CLI
		//    release, upstream would see (new UA + old beta) which is a
		//    deterministic fingerprint signal.
		clientBeta := upstreamReq.Header.Get("Anthropic-Beta")
		ccModel, _ := parsed["model"].(string)
		newBeta := BuildCanonicalBetaHeader(ccModel, clientBeta, strings.Contains(origReq.URL.Path, "count_tokens"))
		delete(upstreamReq.Header, "Anthropic-Beta")
		upstreamReq.Header["anthropic-beta"] = []string{newBeta}
		if clientBeta != newBeta {
			observe.Logger(ctx).Debug("disguise: beta header canonicalized (CC pass-through)",
				"account", accountName,
				"before", clientBeta,
				"after", newBeta,
			)
		}
		// 4. Rewrite metadata.user_id with session masking to prevent cross-user correlation.
		//    Use fp.UserAgent as the version source (not origReq UA) so user_id
		//    format (legacy vs JSON) matches the UA we actually send upstream.
		metadata, ok := parsed["metadata"].(map[string]interface{})
		if !ok {
			metadata = make(map[string]interface{})
		}
		// Observation-only: record any non-standard metadata sibling fields (user_id
		// is the only field real Claude CLI sends — see claude-code
		// src/services/api/claude.ts:519-527). Third-party compatible clients may
		// inject custom fields here; we do NOT strip them (sub2api passes them
		// through as well, following "minimize byte churn" philosophy) but we want
		// to know how often this actually happens on the wire. Field names only —
		// never values, which may be PII.
		if siblings := collectMetadataSiblingFields(metadata); len(siblings) > 0 {
			observe.Logger(ctx).Debug("disguise: metadata sibling fields observed (CC pass-through)",
				"account", accountName,
				"sibling_fields", siblings,
			)
		}
		maskedSession := e.sessions.Get(accountID)
		fpUA := ""
		if fp != nil {
			fpUA = fp.UserAgent
		}
		if fpUA == "" {
			fpUA = DefaultHeaders["User-Agent"]
		}
		uaVersion := extractUAVersion(fpUA)
		originalUserIDRaw := metadata["user_id"]
		// user_id may be a string (old format) or map[string]interface{} (new JSON format >= 2.1.78)
		var originalUserIDStr string
		switch v := originalUserIDRaw.(type) {
		case string:
			originalUserIDStr = v
		case map[string]interface{}:
			// JSON object format: re-marshal to string for ParseUserID
			if b, err := json.Marshal(v); err == nil {
				originalUserIDStr = string(b)
			}
		}
		// Rewrite metadata.user_id: use account's fixed fp.ClientID as device_id so all users
		// appear as the same device (aligned with sub2api's fp.ClientID strategy).
		fpClientID := ""
		if fp != nil {
			fpClientID = fp.ClientID
		}
		rewrittenUserID := RewriteUserIDWithFixedClient(originalUserIDStr, fpClientID, maskedSession, uaVersion)
		// Preserve other metadata fields; only overwrite user_id (session masking).
		metadata["user_id"] = rewrittenUserID
		parsed["metadata"] = metadata
		newUserIDStr := rewrittenUserID
		observe.Logger(ctx).Debug("disguise: user_id rewritten (CC pass-through)",
			"account", accountName,
			"before", truncateUserID(originalUserIDStr),
			"after", truncateUserID(newUserIDStr),
		)
		// Sync X-Claude-Code-Session-Id header with the rewritten session_id (Claude Code 2.1.87+).
		// The header must match metadata.user_id's session_id to avoid Anthropic validation failures.
		if upstreamReq.Header.Get("X-Claude-Code-Session-Id") != "" {
			if p := ParseUserID(newUserIDStr); p != nil {
				upstreamReq.Header.Set("X-Claude-Code-Session-Id", p.SessionID)
				observe.Logger(ctx).Debug("disguise: X-Claude-Code-Session-Id synced (CC pass-through)",
					"account", accountName,
					"session_id", p.SessionID,
				)
			}
		}
		// Enforce cache_control block limit (aligned with sub2api's all-requests enforcement).
		enforceCacheControlLimit(ctx, parsed)

		// Passively probe the client's billing header fingerprint algorithm
		// BEFORE we rewrite anything. Uses the CLIENT's own UA version
		// (not fp UA) because we want to map "what version produced this
		// suffix" — our fp UA lies. See billing_probe.go for dedup policy.
		clientUAVersion := extractUAVersion(origReq.Header.Get("User-Agent"))
		e.billingProbe.ObserveParsedBody(ctx, parsed, clientUAVersion)

		// Canonicalize the billing header to the whitelist-pinned identity:
		// rewrites cc_version (triple + freshly-computed 3hex) and resets
		// cch to the "00000" placeholder. The placeholder is filled in
		// after json.Marshal by rewriteCCHInBody — see cch.go for why
		// the hash must be computed over the marshaled wire bytes.
		// See syncBillingHeaderVersion for the full rationale of why we
		// own all three fields rather than passing client values through.
		if uaVersion != "" {
			syncBillingHeaderVersion(parsed, uaVersion)
		}

		// Rewrite <env> block fingerprint lines to per-account canonical
		// values. Real Claude CLI injects getCwd()/os.platform()/uname -sr
		// into every request; for multi-user shared-account setups the raw
		// values leak which human is behind the token. We guard on Claude
		// Code prompt prefix inside the rewriter so user content is safe.
		rewriteEnvBlockInPlace(parsed, fp)

		// count_tokens endpoint does not accept metadata field — strip it to avoid 400.
		if strings.Contains(origReq.URL.Path, "count_tokens") {
			delete(parsed, "metadata")
		}

		if result, err := json.Marshal(parsed); err == nil {
			body = result
		}

		// Final step on the wire body: rewrite the cch=00000 placeholder
		// with the keyed-xxhash64 of the body. MUST be the very last
		// transform — any byte change after this invalidates the hash.
		// See cch.go for the algorithm and rewriteCCHInBody for the
		// exact contract.
		if rewriteCCHInBody(body) {
			observe.Logger(ctx).Debug("disguise: cch attestation written (CC pass-through)",
				"account", accountName,
			)
		}

		return body, true // true → handler appends ?beta=true
	}

	// Non-CC client: full disguise pipeline
	observe.Logger(ctx).Debug("disguise: non-CC client, applying full disguise",
		"account", accountName,
		"original_ua", origReq.Header.Get("User-Agent"),
	)

	// Parse body once — all layers mutate parsed in-place, marshal once at end
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, false
	}

	model, _ := parsed["model"].(string)
	_, hasTools := parsed["tools"]

	// Layer 7: Thinking cache_control cleanup (before other modifications)
	if CleanThinkingCacheControl(parsed) {
		observe.Logger(ctx).Debug("disguise: [layer 7] thinking cache_control cleaned", "account", accountName)
	}

	// Layer 2: HTTP Headers (per-account fingerprint)
	fp := e.fingerprints.Get(accountID)
	ApplyHeaders(upstreamReq, isStream, fp)
	if fp != nil {
		observe.Logger(ctx).Debug("disguise: [layer 2] headers applied (per-account fingerprint)",
			"account", accountName,
			"original_ua", origReq.Header.Get("User-Agent"),
			"disguised_ua", fp.UserAgent,
			"stainless_os", fp.StainlessOS,
			"stainless_arch", fp.StainlessArch,
		)
	} else {
		observe.Logger(ctx).Debug("disguise: [layer 2] headers applied (default fingerprint)",
			"account", accountName,
			"original_ua", origReq.Header.Get("User-Agent"),
			"disguised_ua", DefaultHeaders["User-Agent"],
		)
	}

	// Layer 3: anthropic-beta
	//
	// Use the single canonical builder so both CC and non-CC paths emit the
	// same token set (and ordering) for a given model. This ensures the
	// context-1m-2025-08-07 token lands immediately after oauth when the
	// client opts in, which matches real Claude CLI traffic order.
	originalBeta := origReq.Header.Get("Anthropic-Beta")
	newBeta := BuildCanonicalBetaHeader(model, originalBeta, strings.Contains(origReq.URL.Path, "count_tokens"))
	delete(upstreamReq.Header, "Anthropic-Beta")
	upstreamReq.Header["anthropic-beta"] = []string{newBeta}
	observe.Logger(ctx).Debug("disguise: [layer 3] beta header set",
		"account", accountName,
		"model", model,
		"has_tools", hasTools,
		"before", originalBeta,
		"after", newBeta,
	)

	// Sanitize third-party tool prompts before system prompt injection
	sanitizeSystemTextInPlace(parsed)

	// Layer 4: System Prompt Injection (skip for Haiku)
	if !IsHaikuModel(model) {
		hasSystemBefore := parsed["system"] != nil
		injectSystemPromptInPlace(parsed)
		observe.Logger(ctx).Debug("disguise: [layer 4] system prompt injected",
			"account", accountName,
			"had_system_before", hasSystemBefore,
		)
	} else {
		observe.Logger(ctx).Debug("disguise: [layer 4] system prompt skipped (haiku model)",
			"account", accountName,
			"model", model,
		)
	}

	// Layer 5: metadata.user_id with session masking
	maskedSession := e.sessions.Get(accountName)
	originalUserID := ""
	if meta, ok := parsed["metadata"].(map[string]interface{}); ok {
		switch v := meta["user_id"].(type) {
		case string:
			originalUserID = v
		case map[string]interface{}:
			if b, err := json.Marshal(v); err == nil {
				originalUserID = string(b)
			}
		}
	}
	// For non-CC path, use the fingerprint UA version to determine user_id format.
	// Default fingerprint is claude-cli/2.1.22, so old format is used by default.
	fpUAVersion := ""
	if fp != nil {
		fpUAVersion = extractUAVersion(fp.UserAgent)
	} else {
		fpUAVersion = extractUAVersion(DefaultHeaders["User-Agent"])
	}
	// Observation-only: record any non-standard metadata sibling fields before
	// the user_id injection. See the CC pass-through path above for rationale.
	if existingMeta, ok := parsed["metadata"].(map[string]interface{}); ok {
		if siblings := collectMetadataSiblingFields(existingMeta); len(siblings) > 0 {
			observe.Logger(ctx).Debug("disguise: metadata sibling fields observed (non-CC disguise)",
				"account", accountName,
				"sibling_fields", siblings,
			)
		}
	}
	injectMetadataUserIDInPlace(parsed, fpClientIDOrEmpty(fp), maskedSession, fpUAVersion)
	newUserID := ""
	if meta, ok := parsed["metadata"].(map[string]interface{}); ok {
		newUserID, _ = meta["user_id"].(string)
	}
	observe.Logger(ctx).Debug("disguise: [layer 5] metadata.user_id set",
		"account", accountName,
		"before", truncateUserID(originalUserID),
		"after", truncateUserID(newUserID),
	)
	// Sync X-Claude-Code-Session-Id header with the generated session_id (Claude Code 2.1.87+).
	if upstreamReq.Header.Get("X-Claude-Code-Session-Id") != "" && newUserID != "" {
		if p := ParseUserID(newUserID); p != nil {
			upstreamReq.Header.Set("X-Claude-Code-Session-Id", p.SessionID)
		}
	}

	// Layer 6: Model ID normalization
	normalizeModelInPlace(parsed)
	if normalizedModel, ok := parsed["model"].(string); ok && normalizedModel != model {
		observe.Logger(ctx).Debug("disguise: [layer 6] model ID normalized",
			"account", accountName,
			"before", model,
			"after", normalizedModel,
		)
	}

	// Layer 8: Body sanitization (match sub2api's normalizeClaudeOAuthRequestBody)
	_, hadTemperature := parsed["temperature"]
	_, hadToolChoice := parsed["tool_choice"]
	_, hadTools := parsed["tools"]
	injectedCM := sanitizeRequestBodyInPlace(parsed)
	if hadTemperature || hadToolChoice || !hadTools || injectedCM {
		observe.Logger(ctx).Debug("disguise: [layer 8] body sanitized",
			"account", accountName,
			"removed_temperature", hadTemperature,
			"removed_tool_choice", hadToolChoice,
			"injected_empty_tools", !hadTools,
			"injected_context_management", injectedCM,
		)
	}

	// Enforce cache_control limit (after all other modifications)
	enforceCacheControlLimit(ctx, parsed)

	// Canonicalize the billing header — same logic as the CC pass-through
	// path. Non-CC clients rarely carry a billing block, but some Claude-
	// compatible clients (e.g. opencode) do; when present, we own it the
	// same way (whitelist version + recomputed 3hex + cch placeholder
	// for the post-marshal rewriter).
	if fpUAVersion != "" {
		syncBillingHeaderVersion(parsed, fpUAVersion)
	}

	// Rewrite <env> block fingerprint lines. Non-CC clients usually don't
	// emit an <env> block at all (this is a Claude CLI thing), but when
	// injectSystemPromptInPlace prepended our canonical Claude Code prefix
	// above, any later sub-agent system block that happens to quote an
	// <env> envelope gets normalized too. Cheap no-op in the common case.
	rewriteEnvBlockInPlace(parsed, fp)

	// count_tokens endpoint does not accept metadata field — strip it to avoid 400.
	if strings.Contains(origReq.URL.Path, "count_tokens") {
		delete(parsed, "metadata")
	}

	// Marshal once at the end
	result, err := json.Marshal(parsed)
	if err != nil {
		return body, true
	}

	// Final step on the wire body: rewrite the cch=00000 placeholder
	// with the keyed-xxhash64 of the body. MUST be the very last
	// transform — any byte change after this invalidates the hash.
	if rewriteCCHInBody(result) {
		observe.Logger(ctx).Debug("disguise: cch attestation written (full disguise)",
			"account", accountName,
		)
	}

	return result, true
}

// truncateUserID returns a shortened user_id for logging: first 12 + last 8 chars.
func truncateUserID(uid string) string {
	if uid == "" {
		return "(empty)"
	}
	if len(uid) <= 24 {
		return uid
	}
	return uid[:12] + "..." + uid[len(uid)-8:]
}

// ApplyToURL appends ?beta=true to the request URL if disguise is active.
func (e *Engine) ApplyToURL(rawURL string) string {
	if strings.Contains(rawURL, "?") {
		return rawURL + "&beta=true"
	}
	return rawURL + "?beta=true"
}

// ApplyResponseModelID reverses model ID mapping on response body.
// Uses a fast path to skip JSON parsing when no reverse-mapped model ID is present.
func (e *Engine) ApplyResponseModelID(body []byte) []byte {
	// Fast path: check if any full versioned model ID appears in the body.
	found := false
	for fullID := range ModelIDReverseOverrides {
		if bytes.Contains(body, []byte(fullID)) {
			found = true
			break
		}
	}
	if !found {
		return body
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}
	if model, ok := resp["model"].(string); ok {
		denormalized := DenormalizeModelID(model)
		if denormalized != model {
			slog.Debug("disguise: response model ID denormalized",
				"before", model,
				"after", denormalized,
			)
			resp["model"] = denormalized
			result, err := json.Marshal(resp)
			if err != nil {
				return body
			}
			return result
		}
	}
	return body
}

const claudeCodeSystemPrompt = "You are Claude Code, Anthropic's official CLI for Claude."

// openCodeReplacements maps third-party tool prompts to Claude Code equivalents.
var openCodeReplacements = [][2]string{
	{"You are OpenCode, the best coding agent on the planet.", claudeCodeSystemPrompt},
}

// sanitizeSystemTextInPlace replaces known third-party tool prompts with
// Claude Code equivalents in the system field of parsed. Mutates in-place.
func sanitizeSystemTextInPlace(parsed map[string]interface{}) {
	system, ok := parsed["system"]
	if !ok {
		return
	}

	switch v := system.(type) {
	case string:
		for _, r := range openCodeReplacements {
			if strings.Contains(v, r[0]) {
				v = strings.ReplaceAll(v, r[0], r[1])
			}
		}
		parsed["system"] = v
	case []interface{}:
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			text, ok := m["text"].(string)
			if !ok {
				continue
			}
			for _, r := range openCodeReplacements {
				if strings.Contains(text, r[0]) {
					text = strings.ReplaceAll(text, r[0], r[1])
					m["text"] = text
				}
			}
		}
	}
}

// injectSystemPromptInPlace injects the Claude Code system prompt into parsed map.
// Mutates parsed in-place. No marshaling.
func injectSystemPromptInPlace(parsed map[string]interface{}) {
	// Check if any system block already contains Claude Code prompt
	if system, ok := parsed["system"]; ok {
		for _, text := range extractAllSystemTexts(system) {
			for _, prefix := range claudeCodePromptPrefixes {
				if strings.HasPrefix(text, prefix) {
					return // already has Claude Code prompt
				}
			}
		}
	}

	claudeCodeBlock := map[string]interface{}{
		"type":          "text",
		"text":          claudeCodeSystemPrompt,
		"cache_control": map[string]string{"type": "ephemeral"},
	}
	claudeCodePrefix := strings.TrimSpace(claudeCodeSystemPrompt)

	var newSystem []interface{}

	switch system := parsed["system"].(type) {
	case nil:
		newSystem = []interface{}{claudeCodeBlock}
	case string:
		trimmed := strings.TrimSpace(system)
		if trimmed == "" || trimmed == claudeCodePrefix {
			newSystem = []interface{}{claudeCodeBlock}
		} else {
			// Place the original system prompt as a separate block.
			// Do NOT prepend claudeCodePrefix again — it is already in claudeCodeBlock.
			newSystem = []interface{}{claudeCodeBlock, map[string]interface{}{"type": "text", "text": system}}
		}
	case []interface{}:
		newSystem = make([]interface{}, 0, len(system)+1)
		newSystem = append(newSystem, claudeCodeBlock)
		for _, item := range system {
			if m, ok := item.(map[string]interface{}); ok {
				if text, ok := m["text"].(string); ok && strings.TrimSpace(text) == claudeCodePrefix {
					continue // skip duplicate Claude Code block
				}
			}
			newSystem = append(newSystem, item)
		}
	default:
		newSystem = []interface{}{claudeCodeBlock}
	}

	parsed["system"] = newSystem
}

func injectMetadataUserIDInPlace(parsed map[string]interface{}, fixedClientID string, maskedSessionUUID string, uaVersion string) {
	clientID := fixedClientID
	if clientID == "" {
		clientID = GenerateClientID()
	}

	sessionID := maskedSessionUUID
	if sessionID == "" {
		sessionID = generateSessionUUID("")
	}

	var userID string
	if isNewMetadataFormatVersion(uaVersion) {
		obj := userIDJSON{DeviceID: clientID, SessionID: sessionID}
		b, _ := json.Marshal(obj)
		userID = string(b)
	} else {
		userID = fmt.Sprintf("user_%s_account__session_%s", clientID, sessionID)
	}

	// Preserve other metadata fields; only set user_id.
	meta, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		meta = make(map[string]interface{})
	}
	meta["user_id"] = userID
	parsed["metadata"] = meta
}

// sanitizeRequestBodyInPlace ensures the request body matches Claude Code client patterns.
// Mutates parsed in-place. No marshaling. Returns whether the canonical
// context_management default was injected so callers can log the event.
func sanitizeRequestBodyInPlace(parsed map[string]interface{}) (injectedCM bool) {
	// Ensure tools field exists (even as empty array)
	if _, exists := parsed["tools"]; !exists {
		parsed["tools"] = []interface{}{}
	}

	// Remove temperature (Claude Code does not send it)
	delete(parsed, "temperature")

	// Remove tool_choice (Claude Code does not send it)
	delete(parsed, "tool_choice")

	// Inject context_management when thinking is enabled.
	//
	// In a 221-sample capture of real Claude CLI 2.1.126/132 traffic, every
	// request with thinking.type ∈ {enabled, adaptive} carried exactly:
	//   {"edits":[{"keep":"all","type":"clear_thinking_20251015"}]}
	// and every request without thinking lacked context_management entirely.
	// The "thinking enabled + no context_management" combination does not
	// appear in real CLI traffic and is a third-party fingerprint signal.
	return injectContextManagementIfThinking(parsed)
}

// injectContextManagementIfThinking sets parsed["context_management"] to the
// canonical Claude CLI default when thinking is enabled but the field is
// absent. No-op when thinking is disabled, missing, or the field is already
// present (client value wins). Returns true iff it actually wrote a value.
func injectContextManagementIfThinking(parsed map[string]interface{}) bool {
	if _, present := parsed["context_management"]; present {
		return false
	}
	thinking, ok := parsed["thinking"].(map[string]interface{})
	if !ok {
		return false
	}
	tType, _ := thinking["type"].(string)
	if tType != "enabled" && tType != "adaptive" {
		return false
	}
	parsed["context_management"] = map[string]interface{}{
		"edits": []interface{}{
			map[string]interface{}{
				"keep": "all",
				"type": "clear_thinking_20251015",
			},
		},
	}
	return true
}

// maxCacheControlBlocks is the maximum number of cache_control blocks allowed
// in a single request (system + messages combined).
const maxCacheControlBlocks = 4

// enforceCacheControlLimit removes excess cache_control blocks when the total
// count exceeds maxCacheControlBlocks. Removal priority:
// 1. Messages from the beginning (oldest), skipping thinking blocks
// 2. System blocks from the end (preserving the injected Claude Code prompt at index 0)
func enforceCacheControlLimit(ctx context.Context, parsed map[string]interface{}) {
	type loc struct {
		parent map[string]interface{}
	}

	var systemLocs, messageLocs []loc

	// Collect cache_control locations from system
	if sysRaw, ok := parsed["system"]; ok {
		if arr, ok := sysRaw.([]interface{}); ok {
			for _, item := range arr {
				if m, ok := item.(map[string]interface{}); ok {
					if _, has := m["cache_control"]; has {
						systemLocs = append(systemLocs, loc{parent: m})
					}
				}
			}
		}
	}

	// Collect cache_control locations from messages
	if msgsRaw, ok := parsed["messages"]; ok {
		if msgs, ok := msgsRaw.([]interface{}); ok {
			for _, msg := range msgs {
				msgMap, ok := msg.(map[string]interface{})
				if !ok {
					continue
				}
				contentRaw, ok := msgMap["content"]
				if !ok {
					continue
				}
				contentArr, ok := contentRaw.([]interface{})
				if !ok {
					continue
				}
				for _, block := range contentArr {
					blockMap, ok := block.(map[string]interface{})
					if !ok {
						continue
					}
					if _, has := blockMap["cache_control"]; !has {
						continue
					}
					// Skip thinking blocks
					if blockType, _ := blockMap["type"].(string); blockType == "thinking" {
						continue
					}
					messageLocs = append(messageLocs, loc{parent: blockMap})
				}
			}
		}
	}

	total := len(systemLocs) + len(messageLocs)
	if total <= maxCacheControlBlocks {
		return
	}

	excess := total - maxCacheControlBlocks
	removedFromMessages := 0
	removedFromSystem := 0

	// Remove from messages first (oldest → newest)
	for i := 0; i < len(messageLocs) && excess > 0; i++ {
		delete(messageLocs[i].parent, "cache_control")
		excess--
		removedFromMessages++
	}

	// Remove from system (from the end, preserving index 0 which is the injected prompt)
	for i := len(systemLocs) - 1; i >= 1 && excess > 0; i-- {
		delete(systemLocs[i].parent, "cache_control")
		excess--
		removedFromSystem++
	}

	observe.Logger(ctx).Debug("disguise: cache_control limit enforced",
		"total_found", total,
		"max_allowed", maxCacheControlBlocks,
		"removed_from_messages", removedFromMessages,
		"removed_from_system", removedFromSystem,
	)
}

// normalizeModelInPlace normalizes the model ID in parsed map in-place.
func normalizeModelInPlace(parsed map[string]interface{}) {
	model, ok := parsed["model"].(string)
	if !ok {
		return
	}
	normalized := NormalizeModelID(model)
	if normalized != model {
		parsed["model"] = normalized
	}
}

// fpClientIDOrEmpty safely retrieves the ClientID from a Fingerprint, returning ""
// when fp is nil (injectMetadataUserIDInPlace handles empty by generating a random one).
func fpClientIDOrEmpty(fp *Fingerprint) string {
	if fp == nil {
		return ""
	}
	return fp.ClientID
}
