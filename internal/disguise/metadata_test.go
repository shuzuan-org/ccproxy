package disguise

import (
	"regexp"
	"testing"
)

var userIDPattern = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account__session_[\w-]+$`)

func TestGenerateClientID_Length(t *testing.T) {
	id := GenerateClientID()
	if len(id) != 64 {
		t.Errorf("expected 64-char hex string, got length %d: %q", len(id), id)
	}
	// Verify it's valid hex.
	hexPattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if !hexPattern.MatchString(id) {
		t.Errorf("expected lowercase hex string, got %q", id)
	}
}

func TestGenerateClientID_Uniqueness(t *testing.T) {
	id1 := GenerateClientID()
	id2 := GenerateClientID()
	if id1 == id2 {
		t.Error("expected different values from two GenerateClientID calls")
	}
}

func TestGenerateUserID_Format(t *testing.T) {
	uid := GenerateUserID("")
	if !userIDPattern.MatchString(uid) {
		t.Errorf("user ID does not match expected format: %q", uid)
	}
}

func TestGenerateUserID_SameSeedSameSessionUUID(t *testing.T) {
	uid1 := GenerateUserID("my-session-seed")
	uid2 := GenerateUserID("my-session-seed")

	// Extract session UUID part (after last "_session_").
	extractSession := func(uid string) string {
		idx := regexp.MustCompile(`_account__session_`).FindStringIndex(uid)
		if idx == nil {
			return ""
		}
		return uid[idx[1]:]
	}

	s1 := extractSession(uid1)
	s2 := extractSession(uid2)
	if s1 != s2 {
		t.Errorf("expected same session UUID for same seed, got %q vs %q", s1, s2)
	}
}

func TestGenerateUserID_DifferentSeedDifferentSessionUUID(t *testing.T) {
	uid1 := GenerateUserID("seed-alpha")
	uid2 := GenerateUserID("seed-beta")

	extractSession := func(uid string) string {
		idx := regexp.MustCompile(`_account__session_`).FindStringIndex(uid)
		if idx == nil {
			return ""
		}
		return uid[idx[1]:]
	}

	s1 := extractSession(uid1)
	s2 := extractSession(uid2)
	if s1 == s2 {
		t.Errorf("expected different session UUID for different seeds, got same: %q", s1)
	}
}

func TestNormalizeModelID_Known(t *testing.T) {
	got := NormalizeModelID("claude-sonnet-4-5")
	if got != "claude-sonnet-4-5-20250929" {
		t.Errorf("expected claude-sonnet-4-5-20250929, got %q", got)
	}
}

func TestNormalizeModelID_Unknown(t *testing.T) {
	got := NormalizeModelID("claude-opus-4-6")
	if got != "claude-opus-4-6" {
		t.Errorf("expected unchanged claude-opus-4-6, got %q", got)
	}
}

func TestDenormalizeModelID_Known(t *testing.T) {
	got := DenormalizeModelID("claude-sonnet-4-5-20250929")
	if got != "claude-sonnet-4-5" {
		t.Errorf("expected claude-sonnet-4-5, got %q", got)
	}
}

func TestDenormalizeModelID_Unknown(t *testing.T) {
	got := DenormalizeModelID("claude-opus-4-6")
	if got != "claude-opus-4-6" {
		t.Errorf("expected unchanged claude-opus-4-6, got %q", got)
	}
}
