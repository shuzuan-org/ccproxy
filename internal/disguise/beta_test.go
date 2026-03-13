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
