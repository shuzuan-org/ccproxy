package disguise

import "testing"

func TestSupplementBetaHeader_Empty(t *testing.T) {
	got := SupplementBetaHeader("")
	if got != BetaOAuth {
		t.Errorf("expected %q for empty input, got %q", BetaOAuth, got)
	}
}

func TestSupplementBetaHeader_AlreadyPresent(t *testing.T) {
	input := BetaClaudeCode + "," + BetaOAuth + "," + BetaInterleavedThinking
	got := SupplementBetaHeader(input)
	if got != input {
		t.Errorf("expected unchanged %q, got %q", input, got)
	}
}

func TestSupplementBetaHeader_MissingOAuth(t *testing.T) {
	input := BetaClaudeCode + "," + BetaInterleavedThinking
	got := SupplementBetaHeader(input)
	want := input + "," + BetaOAuth
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}

func TestSupplementBetaHeader_OnlyClaudeCode(t *testing.T) {
	input := BetaClaudeCode
	got := SupplementBetaHeader(input)
	want := BetaClaudeCode + "," + BetaOAuth
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
}
