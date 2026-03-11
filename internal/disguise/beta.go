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
// All instances are OAuth, so the oauth beta token is always included.
func BetaHeader(model string, hasTools bool) string {
	return BetaOAuth + "," + BetaInterleavedThinking
}

// SupplementBetaHeader preserves the client's existing beta tokens and ensures
// that the oauth-2025-04-20 token is present. Used for real Claude Code clients
// going through OAuth instances (no full disguise, just supplement missing beta).
func SupplementBetaHeader(clientBeta string) string {
	if clientBeta == "" {
		return BetaOAuth
	}
	// Check if oauth beta is already present
	for _, token := range strings.Split(clientBeta, ",") {
		if strings.TrimSpace(token) == BetaOAuth {
			return clientBeta // already has it
		}
	}
	return clientBeta + "," + BetaOAuth
}

// CountTokensBetaHeader returns beta header for count_tokens requests.
func CountTokensBetaHeader() string {
	parts := []string{BetaClaudeCode, BetaOAuth, BetaInterleavedThinking, BetaTokenCounting}
	return strings.Join(parts, ",")
}
