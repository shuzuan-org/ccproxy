package disguise

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/observe"
)

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

		// Real CC client via OAuth: lightweight processing only.
		// 1. Supplement oauth beta header (preserve client's existing betas)
		clientBeta := upstreamReq.Header.Get("Anthropic-Beta")
		newBeta := SupplementBetaHeader(clientBeta)
		upstreamReq.Header.Set("Anthropic-Beta", newBeta)
		if clientBeta != newBeta {
			observe.Logger(ctx).Debug("disguise: beta header supplemented",
				"account", accountName,
				"before", clientBeta,
				"after", newBeta,
			)
		}

		// 2. Rewrite metadata.user_id with session masking to prevent cross-user correlation
		var parsed map[string]interface{}
		if err := json.Unmarshal(body, &parsed); err != nil {
			return body, true
		}
		metadata, ok := parsed["metadata"].(map[string]interface{})
		if !ok {
			metadata = make(map[string]interface{})
		}
		// Filter billing/internal system blocks (CC clients can carry these too)
		filterSystemBlocksByPrefix(parsed)

		maskedSession := e.sessions.Get(accountName)
		originalUserID, _ := metadata["user_id"].(string)
		if originalUserID != "" {
			metadata["user_id"] = RewriteUserIDWithMasking(originalUserID, sessionSeed, maskedSession)
		} else {
			metadata["user_id"] = GenerateUserID(sessionSeed)
		}
		observe.Logger(ctx).Debug("disguise: user_id rewritten (CC pass-through)",
			"account", accountName,
			"before", truncateUserID(originalUserID),
			"after", truncateUserID(metadata["user_id"].(string)),
		)
		parsed["metadata"] = metadata
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
	upstreamReq.Header.Set("Anthropic-Beta", newBeta)
	observe.Logger(ctx).Debug("disguise: [layer 3] beta header set",
		"account", accountName,
		"model", model,
		"has_tools", hasTools,
		"before", originalBeta,
		"after", newBeta,
	)

	// Filter billing/internal system blocks before any system prompt processing
	filterSystemBlocksByPrefix(parsed)

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
		originalUserID, _ = meta["user_id"].(string)
	}
	injectMetadataUserIDInPlace(parsed, sessionSeed, maskedSession)
	newUserID := ""
	if meta, ok := parsed["metadata"].(map[string]interface{}); ok {
		newUserID, _ = meta["user_id"].(string)
	}
	observe.Logger(ctx).Debug("disguise: [layer 5] metadata.user_id set",
		"account", accountName,
		"before", truncateUserID(originalUserID),
		"after", truncateUserID(newUserID),
	)

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
	enforceCacheControlLimit(parsed)

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
					m["text"] = strings.ReplaceAll(text, r[0], r[1])
				}
			}
		}
	}
}

// injectSystemPromptInPlace injects the Claude Code system prompt into parsed map.
// Mutates parsed in-place. No marshaling.
func injectSystemPromptInPlace(parsed map[string]interface{}) {
	// Check if system prompt already contains Claude Code prompt
	if system, ok := parsed["system"]; ok {
		systemText := extractSystemText(system)
		for _, prefix := range claudeCodePromptPrefixes {
			if strings.HasPrefix(systemText, prefix) {
				return // already has Claude Code prompt
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
		prefixedNext := false
		for _, item := range system {
			if m, ok := item.(map[string]interface{}); ok {
				if text, ok := m["text"].(string); ok && strings.TrimSpace(text) == claudeCodePrefix {
					continue // skip duplicate Claude Code block
				}
				// Prefix the first subsequent text block once
				if !prefixedNext {
					if blockType, _ := m["type"].(string); blockType == "text" {
						if text, ok := m["text"].(string); ok && strings.TrimSpace(text) != "" && !strings.HasPrefix(text, claudeCodePrefix) {
							m["text"] = claudeCodePrefix + "\n\n" + text
							prefixedNext = true
						}
					}
				}
			}
			newSystem = append(newSystem, item)
		}
	default:
		newSystem = []interface{}{claudeCodeBlock}
	}

	parsed["system"] = newSystem
}

// injectMetadataUserIDInPlace sets metadata.user_id in parsed map in-place.
func injectMetadataUserIDInPlace(parsed map[string]interface{}, sessionSeed string, maskedSessionUUID string) {
	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
	}
	userID := GenerateUserID(sessionSeed)
	// Replace the session UUID portion with the masked session UUID
	if maskedSessionUUID != "" {
		parts := strings.SplitN(userID, "_account__session_", 2)
		if len(parts) == 2 {
			userID = parts[0] + "_account__session_" + maskedSessionUUID
		}
	}
	metadata["user_id"] = userID
	parsed["metadata"] = metadata
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
func enforceCacheControlLimit(parsed map[string]interface{}) {
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

	// Remove from messages first (oldest → newest)
	for i := 0; i < len(messageLocs) && excess > 0; i++ {
		delete(messageLocs[i].parent, "cache_control")
		excess--
	}

	// Remove from system (from the end, preserving index 0 which is the injected prompt)
	for i := len(systemLocs) - 1; i >= 1 && excess > 0; i-- {
		delete(systemLocs[i].parent, "cache_control")
		excess--
	}
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
