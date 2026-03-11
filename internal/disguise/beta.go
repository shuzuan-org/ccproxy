package disguise

import "strings"

// Beta token constants. Keep in sync with sub2api/internal/pkg/claude/constants.go.
const (
	BetaClaudeCode               = "claude-code-20250219"
	BetaOAuth                    = "oauth-2025-04-20"
	BetaInterleavedThinking      = "interleaved-thinking-2025-05-14"
	BetaFineGrainedToolStreaming = "fine-grained-tool-streaming-2025-05-14"
	BetaTokenCounting            = "token-counting-2024-11-01"
)

// IsHaikuModel returns true if the model is a Haiku variant.
func IsHaikuModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "haiku")
}

// BetaHeader returns the appropriate anthropic-beta header value for mimic mode.
//
// Per sub2api's mitmproxy observation: real Claude CLI messages requests use
// only oauth + interleaved-thinking. The claude-code beta is dropped for mimic
// requests to match observed traffic patterns.
//
// Haiku models do not need claude-code beta at all.
func BetaHeader(model string, hasTools bool, isOAuth bool) string {
	if IsHaikuModel(model) {
		// Haiku: oauth + interleaved-thinking (no claude-code)
		if isOAuth {
			return BetaOAuth + "," + BetaInterleavedThinking
		}
		return BetaInterleavedThinking
	}

	// Opus/Sonnet mimic: oauth + interleaved-thinking
	// (claude-code beta is intentionally excluded per sub2api behavior)
	if isOAuth {
		return BetaOAuth + "," + BetaInterleavedThinking
	}
	return BetaInterleavedThinking
}

// CountTokensBetaHeader returns beta header for count_tokens requests.
func CountTokensBetaHeader(isOAuth bool) string {
	parts := []string{BetaClaudeCode}
	if isOAuth {
		parts = append(parts, BetaOAuth)
	}
	parts = append(parts, BetaInterleavedThinking, BetaTokenCounting)
	return strings.Join(parts, ",")
}
