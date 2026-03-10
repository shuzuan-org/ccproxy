package disguise

import "strings"

const (
	BetaClaudeCode          = "claude-code-20250219"
	BetaOAuth               = "oauth-2025-04-20"
	BetaAdaptiveThinking    = "adaptive-thinking-2026-01-28"
	BetaContextManagement   = "context-management-2025-06-27"
	BetaPromptCaching       = "prompt-caching-scope-2026-01-05"
	BetaEffort              = "effort-2025-11-24"
	BetaInterleavedThinking = "interleaved-thinking-2025-05-14"
	BetaTokenCounting       = "token-counting-2024-11-01"
)

// IsHaikuModel returns true if the model is a Haiku variant.
func IsHaikuModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "haiku")
}

// BetaHeader returns the appropriate anthropic-beta header value based on context.
func BetaHeader(model string, hasTools bool, isOAuth bool) string {
	if IsHaikuModel(model) {
		// Haiku subagent beta set: interleaved-thinking, context-management, prompt-caching, claude-code
		result := strings.Join([]string{BetaInterleavedThinking, BetaContextManagement, BetaPromptCaching, BetaClaudeCode}, ",")
		if isOAuth {
			result = BetaOAuth + "," + result
		}
		return result
	}

	// Default (Opus/Sonnet) beta set
	parts := []string{BetaClaudeCode}
	if isOAuth {
		parts = append(parts, BetaOAuth)
	}
	parts = append(parts, BetaAdaptiveThinking, BetaContextManagement, BetaPromptCaching, BetaEffort)
	return strings.Join(parts, ",")
}

// CountTokensBetaHeader returns beta header for count_tokens requests.
func CountTokensBetaHeader(isOAuth bool) string {
	parts := []string{BetaClaudeCode}
	if isOAuth {
		parts = append(parts, BetaOAuth)
	}
	parts = append(parts, BetaAdaptiveThinking, BetaTokenCounting)
	return strings.Join(parts, ",")
}
