package disguise

import "testing"

// TestBetaHeader_ModelRouting verifies BetaHeader returns the Haiku set for
// Haiku models and the non-Haiku canonical set otherwise. The hasTools flag
// is a no-op since 2.1.88 (documented on BetaHeader) but is exercised here
// to prevent any future regression that re-introduces tool-based branching.
func TestBetaHeader_ModelRouting(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		model    string
		hasTools bool
		want     string
	}{
		{"haiku no tools", "claude-haiku-4-5-20251001", false, HaikuBetaHeader},
		{"haiku with tools", "claude-haiku-4-5", true, HaikuBetaHeader},
		{"sonnet no tools", "claude-opus-4-6", false, DefaultBetaHeader},
		{"sonnet with tools", "claude-sonnet-4-5", true, DefaultBetaHeader},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := BetaHeader(tc.model, tc.hasTools)
			if got != tc.want {
				t.Errorf("BetaHeader(%q, %v) = %q, want %q", tc.model, tc.hasTools, got, tc.want)
			}
		})
	}
}

func TestMergeAnthropicBeta_EmptyIncoming(t *testing.T) {
	t.Parallel()
	got := MergeAnthropicBeta([]string{BetaOAuth, BetaInterleavedThinking}, "")
	want := BetaOAuth + "," + BetaInterleavedThinking
	if got != want {
		t.Errorf("MergeAnthropicBeta empty incoming: expected %q, got %q", want, got)
	}
}

func TestMergeAnthropicBeta_DeduplicatesTokens(t *testing.T) {
	t.Parallel()
	// Incoming already has BetaOAuth — should not duplicate
	got := MergeAnthropicBeta(
		[]string{BetaOAuth, BetaInterleavedThinking},
		BetaOAuth+","+BetaContext1M,
	)
	want := BetaOAuth + "," + BetaInterleavedThinking + "," + BetaContext1M
	if got != want {
		t.Errorf("MergeAnthropicBeta dedup: expected %q, got %q", want, got)
	}
}

func TestMergeAnthropicBeta_PreservesClientExtras(t *testing.T) {
	t.Parallel()
	got := MergeAnthropicBeta(
		[]string{BetaOAuth},
		BetaClaudeCode+","+BetaFastMode,
	)
	want := BetaOAuth + "," + BetaClaudeCode + "," + BetaFastMode
	if got != want {
		t.Errorf("MergeAnthropicBeta extras: expected %q, got %q", want, got)
	}
}

func TestStripBetaTokens_RemovesSpecifiedTokens(t *testing.T) {
	t.Parallel()
	input := BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking
	got := StripBetaTokens(input, []string{BetaClaudeCode})
	want := BetaOAuth + "," + BetaInterleavedThinking
	if got != want {
		t.Errorf("StripBetaTokens: expected %q, got %q", want, got)
	}
}

func TestStripBetaTokens_EmptyInput(t *testing.T) {
	t.Parallel()
	got := StripBetaTokens("", []string{BetaClaudeCode})
	if got != "" {
		t.Errorf("StripBetaTokens empty: expected empty string, got %q", got)
	}
}

func TestStripBetaTokens_NoMatchingTokens(t *testing.T) {
	t.Parallel()
	input := BetaOAuth + "," + BetaInterleavedThinking
	got := StripBetaTokens(input, []string{BetaClaudeCode})
	if got != input {
		t.Errorf("StripBetaTokens no match: expected %q, got %q", input, got)
	}
}

func TestStripBetaTokens_HandlesWhitespace(t *testing.T) {
	t.Parallel()
	input := BetaClaudeCode + " , " + BetaOAuth
	got := StripBetaTokens(input, []string{BetaClaudeCode})
	if got != BetaOAuth {
		t.Errorf("StripBetaTokens whitespace: expected %q, got %q", BetaOAuth, got)
	}
}

// --- BuildCanonicalBetaHeader ---

// TestBuildCanonicalBetaHeader_NonHaikuBaseline pins the exact non-Haiku
// 2.1.88 token order. Token order is itself a fingerprint signal — any
// reordering must be deliberate and cross-checked against real CLI traffic
// AND ../auth2api/src/proxy/claude-api.ts:buildBetaHeader.
func TestBuildCanonicalBetaHeader_NonHaikuBaseline(t *testing.T) {
	t.Parallel()
	got := BuildCanonicalBetaHeader("claude-sonnet-4-5", "", false)
	want := "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20,effort-2025-11-24"
	if got != want {
		t.Errorf("non-Haiku baseline mismatch:\n  want %q\n  got  %q", want, got)
	}
}

// TestBuildCanonicalBetaHeader_HaikuBaseline pins the Haiku 2.1.88 token
// order. Differences from non-Haiku: no claude-code, no advanced-tool-use,
// no effort; adds structured-outputs.
func TestBuildCanonicalBetaHeader_HaikuBaseline(t *testing.T) {
	t.Parallel()
	got := BuildCanonicalBetaHeader("claude-haiku-4-5-20251001", "", false)
	want := "oauth-2025-04-20,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05,structured-outputs-2025-12-15"
	if got != want {
		t.Errorf("Haiku baseline mismatch:\n  want %q\n  got  %q", want, got)
	}
}

// TestBuildCanonicalBetaHeader_Context1MInsertsAfterOauth verifies the
// critical ordering rule: when client opts into context-1m, the token must
// land immediately after oauth-2025-04-20, NOT at the end of the set.
// Real Claude CLI sends it in this exact slot.
func TestBuildCanonicalBetaHeader_Context1MInsertsAfterOauth(t *testing.T) {
	t.Parallel()
	got := BuildCanonicalBetaHeader("claude-sonnet-4-5", BetaContext1M, false)
	want := "claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20,effort-2025-11-24"
	if got != want {
		t.Errorf("context-1m position mismatch:\n  want %q\n  got  %q", want, got)
	}
}

// TestBuildCanonicalBetaHeader_CountTokensPrependsTokenCounting verifies
// that count_tokens requests get token-counting-2024-11-01 prepended, in
// front of claude-code, mirroring auth2api's logic.
func TestBuildCanonicalBetaHeader_CountTokensPrependsTokenCounting(t *testing.T) {
	t.Parallel()
	got := BuildCanonicalBetaHeader("claude-sonnet-4-5", "", true)
	if !contains(got, BetaTokenCounting+",") {
		t.Errorf("expected %q to start with %q,...", got, BetaTokenCounting)
	}
	// Token-counting must come BEFORE claude-code (prepended, not merged).
	if !contains(got, BetaTokenCounting+","+BetaClaudeCode) {
		t.Errorf("expected token-counting immediately before claude-code, got %q", got)
	}
}

// TestBuildCanonicalBetaHeader_ClientExtrasPreserved verifies that
// experimental/conditional client tokens not in the canonical set (e.g.
// fast-mode) are appended at the end without disturbing baseline order.
func TestBuildCanonicalBetaHeader_ClientExtrasPreserved(t *testing.T) {
	t.Parallel()
	got := BuildCanonicalBetaHeader("claude-sonnet-4-5", BetaFastMode, false)
	// Baseline order intact at the start
	if !contains(got, "claude-code-20250219,oauth-2025-04-20,") {
		t.Errorf("baseline order broken: %q", got)
	}
	// fast-mode appears at the end (after the canonical set)
	if got[len(got)-len(BetaFastMode):] != BetaFastMode {
		t.Errorf("expected fast-mode at end, got %q", got)
	}
}

// TestBuildCanonicalBetaHeader_DeduplicatesClientTokens verifies that
// client-provided tokens already in the canonical set don't get duplicated.
func TestBuildCanonicalBetaHeader_DeduplicatesClientTokens(t *testing.T) {
	t.Parallel()
	// Client sends claude-code + oauth + a duplicate of effort.
	clientBeta := BetaClaudeCode + "," + BetaOAuth + "," + BetaEffort
	got := BuildCanonicalBetaHeader("claude-sonnet-4-5", clientBeta, false)
	// Should equal the baseline — no token appears twice.
	want := BuildCanonicalBetaHeader("claude-sonnet-4-5", "", false)
	if got != want {
		t.Errorf("dedup failed:\n  want %q\n  got  %q", want, got)
	}
}

// TestBuildCanonicalBetaHeader_Context1MAndCountTokens verifies that the
// two conditional flags compose correctly: token-counting prepends, then
// context-1m inserts after oauth (which is now position 2, after
// token-counting and claude-code).
func TestBuildCanonicalBetaHeader_Context1MAndCountTokens(t *testing.T) {
	t.Parallel()
	got := BuildCanonicalBetaHeader("claude-sonnet-4-5", BetaContext1M, true)
	want := "token-counting-2024-11-01,claude-code-20250219,oauth-2025-04-20,context-1m-2025-08-07,interleaved-thinking-2025-05-14,redact-thinking-2026-02-12,context-management-2025-06-27,prompt-caching-scope-2026-01-05,advanced-tool-use-2025-11-20,effort-2025-11-24"
	if got != want {
		t.Errorf("compose mismatch:\n  want %q\n  got  %q", want, got)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
