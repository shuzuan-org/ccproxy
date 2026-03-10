package disguise

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Engine orchestrates the 6-layer Claude CLI impersonation.
type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

// Apply modifies the request and body for Claude CLI impersonation.
// Returns the (possibly modified) body and whether disguise was applied.
//
// The 6 layers:
// 1. TLS fingerprint — handled externally by HTTP transport selection
// 2. HTTP headers — User-Agent, X-Stainless-*, etc.
// 3. anthropic-beta — scenario-based beta token composition
// 4. System prompt injection — inject Claude Code system prompt
// 5. metadata.user_id — generate fake user_id
// 6. Model ID normalization — short name → full versioned name
func (e *Engine) Apply(req *http.Request, body []byte, isOAuth bool, isStream bool, sessionSeed string) ([]byte, bool) {
	if !isOAuth {
		return body, false
	}

	if IsClaudeCodeClient(req.Header, body) {
		return body, false
	}

	// Parse body to extract model and check for tools
	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, false
	}

	model, _ := parsed["model"].(string)
	_, hasTools := parsed["tools"]

	// Layer 2: HTTP Headers
	ApplyHeaders(req, isStream)

	// Layer 3: anthropic-beta
	req.Header.Set("Anthropic-Beta", BetaHeader(model, hasTools, isOAuth))

	// Layer 4: System Prompt Injection (skip for Haiku)
	if !IsHaikuModel(model) {
		body = injectSystemPrompt(parsed, body)
		// Re-parse after injection for subsequent layers
		if err := json.Unmarshal(body, &parsed); err == nil {
			_ = parsed
		}
	}

	// Layer 5: metadata.user_id
	body = injectMetadataUserID(parsed, body, sessionSeed)
	// Re-parse after metadata injection for model normalization
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body, true
	}

	// Layer 6: Model ID normalization
	body = normalizeModelInBody(parsed, body)

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

	// Inject as first element in system array.
	// If system is a string, convert to array format.
	// If system is missing, add it.
	switch system := parsed["system"].(type) {
	case string:
		parsed["system"] = []interface{}{
			map[string]interface{}{"type": "text", "text": claudeCodeSystemPrompt},
			map[string]interface{}{"type": "text", "text": system},
		}
	case []interface{}:
		newSystem := make([]interface{}, 0, len(system)+1)
		newSystem = append(newSystem, map[string]interface{}{"type": "text", "text": claudeCodeSystemPrompt})
		newSystem = append(newSystem, system...)
		parsed["system"] = newSystem
	default:
		parsed["system"] = []interface{}{
			map[string]interface{}{"type": "text", "text": claudeCodeSystemPrompt},
		}
	}

	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

func injectMetadataUserID(parsed map[string]interface{}, body []byte, sessionSeed string) []byte {
	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
	}
	metadata["user_id"] = GenerateUserID(sessionSeed)
	parsed["metadata"] = metadata

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
