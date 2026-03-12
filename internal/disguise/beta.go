package disguise

import "strings"

// Beta token constants. Keep in sync with sub2api/internal/pkg/claude/constants.go.
const (
	BetaClaudeCode              = "claude-code-20250219"
	BetaOAuth                   = "oauth-2025-04-20"
	BetaInterleavedThinking     = "interleaved-thinking-2025-05-14"
	BetaFineGrainedToolStreaming = "fine-grained-tool-streaming-2025-05-14"
	BetaTokenCounting           = "token-counting-2024-11-01"
	BetaContext1M               = "context-1m-2025-08-07"
	BetaFastMode                = "fast-mode-2026-02-01"
)

// Pre-composed beta header values for common scenarios.
const (
	// DefaultBetaHeader is used for non-Haiku models with tools.
	DefaultBetaHeader = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking + "," + BetaFineGrainedToolStreaming
	// MessageBetaHeaderNoTools is used for non-Haiku models without tools.
	MessageBetaHeaderNoTools = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking
	// HaikuBetaHeader is used for Haiku models (no claude-code beta).
	HaikuBetaHeader = BetaOAuth + "," + BetaInterleavedThinking
)

// IsHaikuModel returns true if the model is a Haiku variant.
func IsHaikuModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "haiku")
}

// BetaHeader returns the appropriate anthropic-beta header value for mimic mode.
//
// Non-Haiku models include the claude-code beta token. When tools are present,
// fine-grained-tool-streaming is additionally included. Haiku models use a
// minimal set (oauth + interleaved-thinking only).
func BetaHeader(model string, hasTools bool) string {
	if IsHaikuModel(model) {
		return HaikuBetaHeader
	}
	if hasTools {
		return DefaultBetaHeader
	}
	return MessageBetaHeaderNoTools
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
