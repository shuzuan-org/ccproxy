package oauth

import (
	"testing"
)

func TestGenerateVerifier_NonEmpty(t *testing.T) {
	v := GenerateVerifier()
	if v == "" {
		t.Fatal("expected non-empty verifier")
	}
	// 32 bytes base64url (no padding) = 43 chars
	if len(v) != 43 {
		t.Fatalf("expected 43 chars, got %d: %q", len(v), v)
	}
}

func TestGenerateVerifier_Unique(t *testing.T) {
	v1 := GenerateVerifier()
	v2 := GenerateVerifier()
	if v1 == v2 {
		t.Fatalf("expected different verifiers, got same: %q", v1)
	}
}

func TestGenerateChallenge_NonEmpty(t *testing.T) {
	verifier := GenerateVerifier()
	challenge := GenerateChallenge(verifier)
	if challenge == "" {
		t.Fatal("expected non-empty challenge")
	}
}

func TestGenerateChallenge_Deterministic(t *testing.T) {
	verifier := GenerateVerifier()
	c1 := GenerateChallenge(verifier)
	c2 := GenerateChallenge(verifier)
	if c1 != c2 {
		t.Fatalf("expected same challenge for same verifier, got %q and %q", c1, c2)
	}
}

func TestGenerateState_NonEmpty(t *testing.T) {
	s := GenerateState()
	if s == "" {
		t.Fatal("expected non-empty state")
	}
}
