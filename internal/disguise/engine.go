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
}

// NewEngine creates a new disguise engine with per-account fingerprint storage
// and session masking. dataDir is the path to the persistent data directory.
func NewEngine(dataDir string) *Engine {
	return &Engine{
		fingerprints: NewFingerprintStore(dataDir),
		sessions:     NewSessionMaskStore(),
	}
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
func (e *Engine) Apply(origReq *http.Request, upstreamReq *http.Request, body []byte, isStream bool, sessionSeed string, accountName string) ([]byte, bool) {
	ctx := origReq.Context()

	// Detect using origReq which has full client headers (User-Agent, X-App, etc.)
	if IsClaudeCodeClient(origReq.Header, body, origReq.URL.Path) {
		observe.Logger(ctx).Debug("disguise: native Claude Code client detected, lightweight pass-through",
			"account", accountName,
		)
		// Learn fingerprint from real CC client for future disguise use
		e.fingerprints.LearnFromHeaders(accountName, origReq.Header)
		// Get per-account fingerprint (ensures ClientID is initialized for this account).
		fp := e.fingerprints.Get(accountName)

		// Real CC client via OAuth: lightweight processing only.
		// 1. Parse body first — filtering and user_id rewriting both require parsed state.
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return body, true
		}

		// 2. Supplement oauth beta header (preserve client's existing betas)
		clientBeta := upstreamReq.Header.Get("Anthropic-Beta")
		newBeta := SupplementBetaHeader(clientBeta)
		delete(upstreamReq.Header, "Anthropic-Beta")
		upstreamReq.Header["anthropic-beta"] = []string{newBeta}
		if clientBeta != newBeta {
			observe.Logger(ctx).Debug("disguise: beta header supplemented",
				"account", accountName,
				"before", clientBeta,
				"after", newBeta,
			)
		}
		// 3. Rewrite metadata.user_id with session masking to prevent cross-user correlation
		metadata, ok := parsed["metadata"].(map[string]interface{})
		if !ok {
			metadata = make(map[string]interface{})
		}
		maskedSession := e.sessions.Get(accountName)
		uaVersion := extractUAVersion(origReq.Header.Get("User-Agent"))
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

		// count_tokens endpoint does not accept metadata field — strip it to avoid 400.
		if strings.Contains(origReq.URL.Path, "count_tokens") {
			delete(parsed, "metadata")
		}

		if result, err := json.Marshal(parsed); err == nil {
			body = result
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
	fp := e.fingerprints.Get(accountName)
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
	originalBeta := origReq.Header.Get("Anthropic-Beta")
	var newBeta string
	if strings.Contains(origReq.URL.Path, "count_tokens") {
		// count_tokens endpoint needs the token-counting beta
		newBeta = MergeAnthropicBeta(
			[]string{BetaClaudeCode, BetaOAuth, BetaInterleavedThinking, BetaTokenCounting},
			originalBeta,
		)
	} else {
		// Merge required betas with client-provided betas, then strip claude-code
		// for non-CC clients (we add it back via required set for disguise)
		required := []string{BetaOAuth, BetaInterleavedThinking}
		if !IsHaikuModel(model) {
			required = append([]string{BetaClaudeCode}, required...)
		}
		if hasTools {
			required = append(required, BetaFineGrainedToolStreaming)
		}
		newBeta = MergeAnthropicBeta(required, originalBeta)
		// Strip claude-code token that might have leaked from non-CC client
		newBeta = StripBetaTokens(newBeta, []string{BetaClaudeCode})
		// Re-add for non-Haiku models (disguise requires it)
		if !IsHaikuModel(model) {
			newBeta = BetaClaudeCode + "," + newBeta
		}
	}
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
	sanitizeRequestBodyInPlace(parsed)
	if hadTemperature || hadToolChoice || !hadTools {
		observe.Logger(ctx).Debug("disguise: [layer 8] body sanitized",
			"account", accountName,
			"removed_temperature", hadTemperature,
			"removed_tool_choice", hadToolChoice,
			"injected_empty_tools", !hadTools,
		)
	}

	// Enforce cache_control limit (after all other modifications)
	enforceCacheControlLimit(ctx, parsed)

	// count_tokens endpoint does not accept metadata field — strip it to avoid 400.
	if strings.Contains(origReq.URL.Path, "count_tokens") {
		delete(parsed, "metadata")
	}

	// Marshal once at the end
	result, err := json.Marshal(parsed)
	if err != nil {
		return body, true
	}
	return result, true
}

// systemBlockFilterPrefixes lists text prefixes that identify system blocks which
// should be removed before forwarding to upstream. These blocks are injected by
// the Anthropic client SDK and expose billing/internal metadata.
var systemBlockFilterPrefixes = []string{"x-anthropic-billing-header"}

// filterSystemBlocksByPrefix removes system blocks whose text starts with any
// of the systemBlockFilterPrefixes. Handles both string and array system fields.
// Mutates parsed in-place.
func filterSystemBlocksByPrefix(parsed map[string]interface{}) {
	system, ok := parsed["system"]
	if !ok {
		return
	}

	switch v := system.(type) {
	case string:
		trimmed := strings.TrimSpace(v)
		for _, prefix := range systemBlockFilterPrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				delete(parsed, "system")
				return
			}
		}
	case []interface{}:
		filtered := make([]interface{}, 0, len(v))
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				filtered = append(filtered, item)
				continue
			}
			text, ok := m["text"].(string)
			if !ok {
				filtered = append(filtered, item)
				continue
			}
			trimmed := strings.TrimSpace(text)
			skip := false
			for _, prefix := range systemBlockFilterPrefixes {
				if strings.HasPrefix(trimmed, prefix) {
					skip = true
					break
				}
			}
			if !skip {
				filtered = append(filtered, item)
			}
		}
		if len(filtered) == 0 {
			delete(parsed, "system")
		} else {
			parsed["system"] = filtered
		}
	}
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
// Mutates parsed in-place. No marshaling.
func sanitizeRequestBodyInPlace(parsed map[string]interface{}) {
	// Ensure tools field exists (even as empty array)
	if _, exists := parsed["tools"]; !exists {
		parsed["tools"] = []interface{}{}
	}

	// Remove temperature (Claude Code does not send it)
	delete(parsed, "temperature")

	// Remove tool_choice (Claude Code does not send it)
	delete(parsed, "tool_choice")
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
