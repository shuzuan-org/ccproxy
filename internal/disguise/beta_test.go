package disguise

import "testing"

func TestBetaHeader_HaikuModel(t *testing.T) {
	t.Parallel()
	got := BetaHeader("claude-haiku-4-5-20251001", false)
	if got != HaikuBetaHeader {
		t.Errorf("Haiku: expected %q, got %q", HaikuBetaHeader, got)
	}
}

func TestBetaHeader_NonHaikuWithTools(t *testing.T) {
	t.Parallel()
	got := BetaHeader("claude-sonnet-4-5", true)
	if got != DefaultBetaHeader {
		t.Errorf("NonHaiku+tools: expected %q, got %q", DefaultBetaHeader, got)
	}
}

func TestBetaHeader_NonHaikuNoTools(t *testing.T) {
	t.Parallel()
	got := BetaHeader("claude-opus-4-6", false)
	if got != MessageBetaHeaderNoTools {
		t.Errorf("NonHaiku-notools: expected %q, got %q", MessageBetaHeaderNoTools, got)
	}
}

func TestBetaHeader_HaikuIgnoresTools(t *testing.T) {
	t.Parallel()
	// Even with hasTools=true, Haiku should use HaikuBetaHeader.
	got := BetaHeader("claude-haiku-4-5", true)
	if got != HaikuBetaHeader {
		t.Errorf("Haiku+tools: expected %q, got %q", HaikuBetaHeader, got)
	}
}

func TestSupplementBetaHeader_Empty(t *testing.T) {
	t.Parallel()
	got := SupplementBetaHeader("")
	if got != BetaOAuth {
		t.Errorf("expected %q for empty input, got %q", BetaOAuth, got)
	}
}

func TestSupplementBetaHeader_AlreadyPresent(t *testing.T) {
	t.Parallel()
	input := BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking
	got := SupplementBetaHeader(input)
	if got != input {
		t.Errorf("expected unchanged %q, got %q", input, got)
	}
}

func TestSupplementBetaHeader_MissingOAuth(t *testing.T) {
	t.Parallel()
	input := BetaClaudeCode + "," + BetaInterleavedThinking
	got := SupplementBetaHeader(input)
	want := input + "," + BetaOAuth
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestSupplementBetaHeader_OnlyClaudeCode(t *testing.T) {
	t.Parallel()
	input := BetaClaudeCode
	got := SupplementBetaHeader(input)
	want := BetaClaudeCode + "," + BetaOAuth
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestCountTokensBetaHeaderValue(t *testing.T) {
	t.Parallel()
	result := CountTokensBetaHeaderValue
	for _, expected := range []string{BetaClaudeCode, BetaOAuth, BetaInterleavedThinking, BetaTokenCounting} {
		if !contains(result, expected) {
			t.Errorf("expected %q in %q", expected, result)
		}
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
