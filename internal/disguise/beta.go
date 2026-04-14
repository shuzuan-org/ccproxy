package disguise

import "strings"

// Beta token constants. Aligned with Claude CLI 2.1.88 observed traffic (2026-04).
const (
	// Original 2025 set
	BetaClaudeCode               = "claude-code-20250219"
	BetaOAuth                    = "oauth-2025-04-20"
	BetaInterleavedThinking      = "interleaved-thinking-2025-05-14"
	BetaFineGrainedToolStreaming = "fine-grained-tool-streaming-2025-05-14"
	BetaTokenCounting            = "token-counting-2024-11-01"
	BetaContext1M                = "context-1m-2025-08-07"
	BetaFastMode                 = "fast-mode-2026-02-01"

	// 2026 additions (observed in Claude CLI >= 2.1.81)
	BetaRedactThinking     = "redact-thinking-2026-02-12"
	BetaContextManagement  = "context-management-2025-06-27"
	BetaPromptCachingScope = "prompt-caching-scope-2026-01-05"
	BetaAdvancedToolUse    = "advanced-tool-use-2025-11-20"
	BetaEffort             = "effort-2025-11-24"
	BetaStructuredOutputs  = "structured-outputs-2025-12-15"
)

// baseBetasNonHaiku is the canonical 2.1.88 non-Haiku beta set. The order
// is the one observed in real Claude CLI traffic and must be preserved —
// anthropic-beta token order is itself a fingerprint signal.
//
// Conditional tokens that are NOT in this base set:
//   - context-1m-2025-08-07: inserted after oauth when the client opts in
//     (see insertContext1M). Real Claude CLI also only sends it when the
//     caller requests the 1M context window.
//   - token-counting-2024-11-01: prepended for /v1/messages/count_tokens
//     requests only.
//   - fast-mode-2026-02-01: preserved verbatim from client input (pass-through).
//
// Cross-checked against ../auth2api/src/proxy/claude-api.ts:buildBetaHeader.
var baseBetasNonHaiku = []string{
	BetaClaudeCode,
	BetaOAuth,
	BetaInterleavedThinking,
	BetaRedactThinking,
	BetaContextManagement,
	BetaPromptCachingScope,
	BetaAdvancedToolUse,
	BetaEffort,
}

// baseBetasHaiku is the canonical 2.1.88 Haiku beta set. Differences from
// non-Haiku: no claude-code, no advanced-tool-use, no effort; adds
// structured-outputs. Cross-checked against auth2api buildBetaHeader.
var baseBetasHaiku = []string{
	BetaOAuth,
	BetaInterleavedThinking,
	BetaRedactThinking,
	BetaContextManagement,
	BetaPromptCachingScope,
	BetaStructuredOutputs,
}

// Pre-composed beta header values for common scenarios.
var (
	// DefaultBetaHeader is the non-Haiku canonical set. Since 2.1.88 the beta
	// set no longer differs with tools-vs-no-tools, so this is also the no-tools
	// value — MessageBetaHeaderNoTools is kept as an alias for callers that
	// prefer the more descriptive name.
	DefaultBetaHeader        = strings.Join(baseBetasNonHaiku, ",")
	MessageBetaHeaderNoTools = DefaultBetaHeader
	// HaikuBetaHeader is the Haiku canonical set (no claude-code token).
	HaikuBetaHeader = strings.Join(baseBetasHaiku, ",")
	// Context1MBetaHeader is the non-Haiku set with context-1m inserted after
	// oauth — used when a non-Haiku request opts into the 1M context window.
	// See BuildCanonicalBetaHeader for the usage logic.
	Context1MBetaHeader = strings.Join(insertContext1M(baseBetasNonHaiku), ",")
)

// insertContext1M returns a copy of base with BetaContext1M inserted after
// BetaOAuth, matching the order observed in auth2api's buildBetaHeader.
func insertContext1M(base []string) []string {
	out := make([]string, 0, len(base)+1)
	for _, tok := range base {
		out = append(out, tok)
		if tok == BetaOAuth {
			out = append(out, BetaContext1M)
		}
	}
	return out
}

// IsHaikuModel returns true if the model is a Haiku variant.
func IsHaikuModel(model string) bool {
	return strings.Contains(model, "haiku") || strings.Contains(model, "Haiku")
}

// BetaHeader returns the appropriate anthropic-beta header value for mimic mode.
//
// Non-Haiku models use the full 2.1.88 canonical set including claude-code.
// Haiku models use a reduced set without claude-code.
// The hasTools flag is kept for API compatibility but no longer affects the
// selection — modern Claude CLI sends the same beta set regardless of tools.
func BetaHeader(model string, hasTools bool) string {
	_ = hasTools
	if IsHaikuModel(model) {
		return HaikuBetaHeader
	}
	return DefaultBetaHeader
}

// BuildCanonicalBetaHeader builds the anthropic-beta header value we send
// upstream for a given (model, client-provided-beta, is-count-tokens) tuple.
// This is the single entry point used by both the non-CC disguise path and
// the CC lightweight path — both paths must emit the same canonical set so
// that the UA we inject (always the fingerprint UA) and the beta set are
// consistent with a single CLI release.
//
// Token ordering matches the reference in auth2api buildBetaHeader:
//
//  1. Start from baseBetasHaiku for Haiku, baseBetasNonHaiku otherwise.
//  2. If the client opted into context-1m (via its own anthropic-beta or
//     explicit body flag), insert context-1m-2025-08-07 right after oauth —
//     NOT at the end of the set. Real CLI sends it in that exact slot.
//  3. For count_tokens requests, prepend token-counting-2024-11-01.
//  4. Preserve any additional client-provided tokens that aren't already
//     in the canonical set (e.g. fast-mode-2026-02-01), appended at the end.
//     This lets experimental beta flags flow through without needing a code
//     change here, while the load-bearing set stays pinned.
//
// clientBeta is the raw comma-separated value the client sent (may be empty).
func BuildCanonicalBetaHeader(model, clientBeta string, isCountTokens bool) string {
	var base []string
	if IsHaikuModel(model) {
		base = append(base, baseBetasHaiku...)
	} else {
		base = append(base, baseBetasNonHaiku...)
	}

	// context-1m positioning: client opt-in triggers the after-oauth insertion.
	// For Haiku, context-1m is not part of the canonical set and upstream may
	// not accept it; we still honor a client opt-in by inserting after oauth
	// so the token order remains consistent, but Anthropic may reject — that's
	// the client's choice, not ours to override silently.
	if strings.Contains(clientBeta, BetaContext1M) {
		base = insertContext1M(base)
	}

	if isCountTokens {
		base = append([]string{BetaTokenCounting}, base...)
	}

	// Preserve client extras not already in base (fast-mode, experimental flags).
	seen := make(map[string]bool, len(base))
	for _, t := range base {
		seen[strings.TrimSpace(t)] = true
	}
	result := make([]string, len(base))
	copy(result, base)
	if clientBeta != "" {
		for _, token := range strings.Split(clientBeta, ",") {
			token = strings.TrimSpace(token)
			if token == "" || seen[token] {
				continue
			}
			seen[token] = true
			result = append(result, token)
		}
	}

	return strings.Join(result, ",")
}

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
