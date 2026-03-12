package disguise

import (
	"context"
	"encoding/json"
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
		// Real CC client via OAuth: lightweight processing only.
		// 1. Supplement oauth beta header (preserve client's existing betas)
		clientBeta := upstreamReq.Header.Get("Anthropic-Beta")
		upstreamReq.Header.Set("Anthropic-Beta", SupplementBetaHeader(clientBeta))

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
		if originalUserID, ok := metadata["user_id"].(string); ok {
			metadata["user_id"] = RewriteUserIDWithMasking(originalUserID, sessionSeed, maskedSession)
		} else {
			metadata["user_id"] = GenerateUserID(sessionSeed)
		}
		parsed["metadata"] = metadata
		if result, err := json.Marshal(parsed); err == nil {
			body = result
		}

		return body, true // true → handler appends ?beta=true
	}

	// Parse body to extract model and check for tools
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, false
	}

	model, _ := parsed["model"].(string)
	_, hasTools := parsed["tools"]

	// Layer 7: Thinking cache_control cleanup (before other modifications)
	if CleanThinkingCacheControl(parsed) {
		if result, err := json.Marshal(parsed); err == nil {
			body = result
		}
	}

	// Layer 2: HTTP Headers (per-instance fingerprint)
	fp := e.fingerprints.Get(instanceName)
	ApplyHeaders(upstreamReq, isStream, fp)

	// Layer 3: anthropic-beta
	upstreamReq.Header.Set("Anthropic-Beta", BetaHeader(model, hasTools))

	// Layer 4: System Prompt Injection (skip for Haiku)
	if !IsHaikuModel(model) {
		body = injectSystemPrompt(parsed, body)
		// Re-parse after injection for subsequent layers
		if err := json.Unmarshal(body, &parsed); err == nil {
			_ = parsed
		}
	}

	// Layer 5: metadata.user_id with session masking
	maskedSession := e.sessions.Get(instanceName)
	body = injectMetadataUserIDWithMasking(parsed, body, sessionSeed, maskedSession)
	// Re-parse after metadata injection for model normalization
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, true
	}

	// Layer 6: Model ID normalization
	body = normalizeModelInBody(parsed, body)
	// Re-parse for sanitization
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, true
	}

	// Layer 8: Body sanitization (match sub2api's normalizeClaudeOAuthRequestBody)
	body = sanitizeRequestBody(parsed, body)

	return body, true
}

// ApplyToURL appends ?beta=true to the request URL if disguise is active.
func (e *Engine) ApplyToURL(rawURL string) string {
	if strings.Contains(rawURL, "?") {
		return rawURL + "&beta=true"
	}
	return rawURL + "?beta=true"
}

// ApplyResponseModelID reverses model ID mapping on response body.
func (e *Engine) ApplyResponseModelID(body []byte) []byte {
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		return body
	}
	if model, ok := resp["model"].(string); ok {
		denormalized := DenormalizeModelID(model)
		if denormalized != model {
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

// injectSystemPrompt injects the Claude Code system prompt into the request body.
// Matches sub2api's injectClaudeCodePrompt: uses cache_control ephemeral block
// and prefixes the next text block with the banner.
func injectSystemPrompt(parsed map[string]interface{}, body []byte) []byte {
	// Check if system prompt already contains Claude Code prompt
	if system, ok := parsed["system"]; ok {
		systemText := extractSystemText(system)
		for _, prefix := range claudeCodePromptPrefixes {
			if strings.HasPrefix(systemText, prefix) {
				return body // already has Claude Code prompt
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
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

func injectMetadataUserIDWithMasking(parsed map[string]interface{}, body []byte, sessionSeed string, maskedSessionUUID string) []byte {
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

	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

// sanitizeRequestBody ensures the request body matches Claude Code client patterns.
// Matches sub2api's normalizeClaudeOAuthRequestBody: inject empty tools array,
// remove temperature and tool_choice fields.
func sanitizeRequestBody(parsed map[string]interface{}, body []byte) []byte {
	modified := false

	// Ensure tools field exists (even as empty array)
	if _, exists := parsed["tools"]; !exists {
		parsed["tools"] = []interface{}{}
		modified = true
	}

	// Remove temperature (Claude Code does not send it)
	if _, exists := parsed["temperature"]; exists {
		delete(parsed, "temperature")
		modified = true
	}

	// Remove tool_choice (Claude Code does not send it)
	if _, exists := parsed["tool_choice"]; exists {
		delete(parsed, "tool_choice")
		modified = true
	}

	if !modified {
		return body
	}

	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

func normalizeModelInBody(parsed map[string]interface{}, body []byte) []byte {
	model, ok := parsed["model"].(string)
	if !ok {
		return body
	}
	normalized := NormalizeModelID(model)
	if normalized == model {
		return body
	}
	parsed["model"] = normalized
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}
