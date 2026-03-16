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
	return strings.Contains(model, "haiku") || strings.Contains(model, "Haiku")
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
// going through OAuth accounts (no full disguise, just supplement missing beta).
func SupplementBetaHeader(clientBeta string) string {
	if clientBeta == "" {
		return BetaOAuth
	}
	// Check if oauth beta is already present
	if strings.Contains(clientBeta, BetaOAuth) {
		return clientBeta
	}
	return clientBeta + "," + BetaOAuth
}

// CountTokensBetaHeaderValue is the pre-composed beta header for count_tokens requests.
const CountTokensBetaHeaderValue = BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking + "," + BetaTokenCounting

// MergeAnthropicBeta merges required beta tokens with client-provided betas,
// deduplicating tokens. Required tokens appear first, followed by any additional
// client tokens not already in the required set.
func MergeAnthropicBeta(required []string, incoming string) string {
	seen := make(map[string]bool, len(required))
	for _, r := range required {
		seen[strings.TrimSpace(r)] = true
	}

	result := make([]string, len(required))
	copy(result, required)

	if incoming != "" {
		for _, token := range strings.Split(incoming, ",") {
			token = strings.TrimSpace(token)
			if token != "" && !seen[token] {
				seen[token] = true
				result = append(result, token)
			}
		}
	}

	return strings.Join(result, ",")
}

// StripBetaTokens removes specified tokens from a comma-separated beta header.
// Returns the cleaned header with removed tokens excluded.
func StripBetaTokens(header string, tokens []string) string {
	if header == "" {
		return ""
	}

	strip := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		strip[strings.TrimSpace(t)] = true
	}

	parts := strings.Split(header, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" && !strip[p] {
			result = append(result, p)
		}
	}

	return strings.Join(result, ",")
}
