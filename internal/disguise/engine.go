package disguise

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Engine orchestrates the multi-layer Claude CLI impersonation.
type Engine struct {
	fingerprints *FingerprintStore
	sessions     *SessionMaskStore
}

// NewEngine creates a new disguise engine with per-instance fingerprint storage
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
// instanceName identifies which proxy instance is being used (for per-instance fingerprinting).
//
// The layers:
// 1. TLS fingerprint — handled externally by HTTP transport selection
// 2. HTTP headers — User-Agent, X-Stainless-*, etc. (per-instance fingerprint)
// 3. anthropic-beta — scenario-based beta token composition
// 4. System prompt injection — inject Claude Code system prompt
// 5. metadata.user_id — generate/rewrite fake user_id with session masking
// 6. Model ID normalization — short name → full versioned name
// 7. Thinking cache_control cleanup — remove cache_control from thinking blocks
// 8. Body sanitization — tools injection, field removal
func (e *Engine) Apply(origReq *http.Request, upstreamReq *http.Request, body []byte, isStream bool, sessionSeed string, instanceName string) ([]byte, bool) {
	// Detect using origReq which has full client headers (User-Agent, X-App, etc.)
	if IsClaudeCodeClient(origReq.Header, body, origReq.URL.Path) {
		slog.Debug("disguise: native Claude Code client detected, lightweight pass-through",
			"instance", instanceName,
		)
		// Real CC client via OAuth: lightweight processing only.
		// 1. Supplement oauth beta header (preserve client's existing betas)
		clientBeta := upstreamReq.Header.Get("Anthropic-Beta")
		newBeta := SupplementBetaHeader(clientBeta)
		upstreamReq.Header.Set("Anthropic-Beta", newBeta)
		if clientBeta != newBeta {
			slog.Debug("disguise: beta header supplemented",
				"instance", instanceName,
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
		maskedSession := e.sessions.Get(instanceName)
		originalUserID, _ := metadata["user_id"].(string)
		if originalUserID != "" {
			metadata["user_id"] = RewriteUserIDWithMasking(originalUserID, sessionSeed, maskedSession)
		} else {
			metadata["user_id"] = GenerateUserID(sessionSeed)
		}
		slog.Debug("disguise: user_id rewritten (CC pass-through)",
			"instance", instanceName,
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
	slog.Debug("disguise: non-CC client, applying full disguise",
		"instance", instanceName,
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
		slog.Debug("disguise: [layer 7] thinking cache_control cleaned", "instance", instanceName)
	}

	// Layer 2: HTTP Headers (per-instance fingerprint)
	fp := e.fingerprints.Get(instanceName)
	ApplyHeaders(upstreamReq, isStream, fp)
	if fp != nil {
		slog.Debug("disguise: [layer 2] headers applied (per-instance fingerprint)",
			"instance", instanceName,
			"original_ua", origReq.Header.Get("User-Agent"),
			"disguised_ua", fp.UserAgent,
			"stainless_os", fp.StainlessOS,
			"stainless_arch", fp.StainlessArch,
		)
	} else {
		slog.Debug("disguise: [layer 2] headers applied (default fingerprint)",
			"instance", instanceName,
			"original_ua", origReq.Header.Get("User-Agent"),
			"disguised_ua", DefaultHeaders["User-Agent"],
		)
	}

	// Layer 3: anthropic-beta
	originalBeta := origReq.Header.Get("Anthropic-Beta")
	newBeta := BetaHeader(model, hasTools)
	upstreamReq.Header.Set("Anthropic-Beta", newBeta)
	slog.Debug("disguise: [layer 3] beta header set",
		"instance", instanceName,
		"model", model,
		"has_tools", hasTools,
		"before", originalBeta,
		"after", newBeta,
	)

	// Layer 4: System Prompt Injection (skip for Haiku)
	if !IsHaikuModel(model) {
		hasSystemBefore := parsed["system"] != nil
		injectSystemPromptInPlace(parsed)
		slog.Debug("disguise: [layer 4] system prompt injected",
			"instance", instanceName,
			"had_system_before", hasSystemBefore,
		)
	} else {
		slog.Debug("disguise: [layer 4] system prompt skipped (haiku model)",
			"instance", instanceName,
			"model", model,
		)
	}

	// Layer 5: metadata.user_id with session masking
	maskedSession := e.sessions.Get(instanceName)
	originalUserID := ""
	if meta, ok := parsed["metadata"].(map[string]interface{}); ok {
		originalUserID, _ = meta["user_id"].(string)
	}
	injectMetadataUserIDInPlace(parsed, sessionSeed, maskedSession)
	newUserID := ""
	if meta, ok := parsed["metadata"].(map[string]interface{}); ok {
		newUserID, _ = meta["user_id"].(string)
	}
	slog.Debug("disguise: [layer 5] metadata.user_id set",
		"instance", instanceName,
		"before", truncateUserID(originalUserID),
		"after", truncateUserID(newUserID),
	)

	// Layer 6: Model ID normalization
	normalizeModelInPlace(parsed)
	if normalizedModel, ok := parsed["model"].(string); ok && normalizedModel != model {
		slog.Debug("disguise: [layer 6] model ID normalized",
			"instance", instanceName,
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
		slog.Debug("disguise: [layer 8] body sanitized",
			"instance", instanceName,
			"removed_temperature", hadTemperature,
			"removed_tool_choice", hadToolChoice,
			"injected_empty_tools", !hadTools,
		)
	}

	// Marshal once at the end
	result, err := json.Marshal(parsed)
	if err != nil {
		return body, true
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
			merged := system
			if !strings.HasPrefix(system, claudeCodePrefix) {
				merged = claudeCodePrefix + "\n\n" + system
			}
			newSystem = []interface{}{claudeCodeBlock, map[string]interface{}{"type": "text", "text": merged}}
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
