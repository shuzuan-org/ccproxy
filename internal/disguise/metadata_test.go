package disguise

import (
	"regexp"
	"strings"
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

// --- RewriteUserID tests ---

func TestRewriteUserID_FormatA(t *testing.T) {
	original := "user_" + strings.Repeat("ab", 32) + "_account__session_abc-123-def"
	result := RewriteUserID(original, "my-account-seed")

	if !userIDPattern.MatchString(result) {
		t.Errorf("rewritten user_id does not match format A: %q", result)
	}
	if result == original {
		t.Error("expected rewritten user_id to differ from original")
	}
}

func TestRewriteUserID_FormatB(t *testing.T) {
	original := "user_" + strings.Repeat("cd", 32) + "_account_acc-uuid-123_session_sess-uuid-456"
	result := RewriteUserID(original, "my-account-seed")

	// Format B: user_{hex}_account_{uuid}_session_{uuid}
	formatB := regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account_[\w-]+_session_[\w-]+$`)
	if !formatB.MatchString(result) {
		t.Errorf("rewritten user_id does not match format B: %q", result)
	}
	if result == original {
		t.Error("expected rewritten user_id to differ from original")
	}
}

func TestRewriteUserID_Deterministic(t *testing.T) {
	original := "user_" + strings.Repeat("ab", 32) + "_account__session_abc-123-def"
	r1 := RewriteUserID(original, "seed-x")
	r2 := RewriteUserID(original, "seed-x")
	if r1 != r2 {
		t.Errorf("expected deterministic output, got %q vs %q", r1, r2)
	}
}

func TestRewriteUserID_DifferentSeedsDifferentOutput(t *testing.T) {
	original := "user_" + strings.Repeat("ab", 32) + "_account__session_abc-123-def"
	r1 := RewriteUserID(original, "seed-a")
	r2 := RewriteUserID(original, "seed-b")
	if r1 == r2 {
		t.Errorf("expected different output for different seeds, got same: %q", r1)
	}
}

func TestRewriteUserID_UnknownFormat_Fallback(t *testing.T) {
	result := RewriteUserID("some-random-user-id", "seed")
	if !userIDPattern.MatchString(result) {
		t.Errorf("fallback user_id does not match expected format: %q", result)
	}
}

// --- RewriteUserIDWithMasking tests ---

func TestRewriteUserIDWithMasking_FormatA(t *testing.T) {
	t.Parallel()
	original := "user_" + strings.Repeat("ab", 32) + "_account__session_abc-123-def"
	masked := "masked-uuid-1234"
	result := RewriteUserIDWithMasking(original, "my-seed", masked)

	if !strings.Contains(result, masked) {
		t.Errorf("expected masked session UUID %q in result %q", masked, result)
	}
	if result == original {
		t.Error("expected rewritten user_id to differ from original")
	}
}

func TestRewriteUserIDWithMasking_FormatB(t *testing.T) {
	t.Parallel()
	original := "user_" + strings.Repeat("cd", 32) + "_account_acc-uuid-123_session_sess-uuid-456"
	masked := "masked-uuid-5678"
	result := RewriteUserIDWithMasking(original, "my-seed", masked)

	if !strings.Contains(result, masked) {
		t.Errorf("expected masked session UUID %q in result %q", masked, result)
	}
}

func TestRewriteUserIDWithMasking_UnknownFormat(t *testing.T) {
	t.Parallel()
	masked := "masked-uuid-9999"
	result := RewriteUserIDWithMasking("random-id", "seed", masked)

	if !strings.Contains(result, masked) {
		t.Errorf("expected masked session UUID %q in fallback result %q", masked, result)
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

// --- ParseUserID tests ---

func TestParseUserID_OldFormatA(t *testing.T) {
	t.Parallel()
	raw := "user_" + strings.Repeat("ab", 32) + "_account__session_abc-123-def"
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID for format A")
	}
	if p.DeviceID != strings.Repeat("ab", 32) {
		t.Errorf("unexpected DeviceID: %q", p.DeviceID)
	}
	if p.SessionID != "abc-123-def" {
		t.Errorf("unexpected SessionID: %q", p.SessionID)
	}
	if p.IsNewFormat {
		t.Error("expected IsNewFormat=false for old format A")
	}
}

func TestParseUserID_OldFormatB(t *testing.T) {
	t.Parallel()
	raw := "user_" + strings.Repeat("cd", 32) + "_account_acc-uuid_session_sess-uuid"
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID for format B")
	}
	if p.AccountUUID != "acc-uuid" {
		t.Errorf("unexpected AccountUUID: %q", p.AccountUUID)
	}
}

func TestParseUserID_NewJSONFormat(t *testing.T) {
	t.Parallel()
	raw := `{"device_id":"` + strings.Repeat("ab", 32) + `","account_uuid":"acc-uuid","session_id":"sess-uuid"}`
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID for JSON format")
	}
	if !p.IsNewFormat {
		t.Error("expected IsNewFormat=true")
	}
	if p.DeviceID != strings.Repeat("ab", 32) {
		t.Errorf("unexpected DeviceID: %q", p.DeviceID)
	}
	if p.SessionID != "sess-uuid" {
		t.Errorf("unexpected SessionID: %q", p.SessionID)
	}
	if p.AccountUUID != "acc-uuid" {
		t.Errorf("unexpected AccountUUID: %q", p.AccountUUID)
	}
}

func TestParseUserID_NewJSONFormat_NoAccountUUID(t *testing.T) {
	t.Parallel()
	raw := `{"device_id":"` + strings.Repeat("ef", 32) + `","session_id":"sess-abc"}`
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID")
	}
	if p.AccountUUID != "" {
		t.Errorf("expected empty AccountUUID, got %q", p.AccountUUID)
	}
}

func TestParseUserID_Invalid(t *testing.T) {
	t.Parallel()
	if ParseUserID("random-garbage") != nil {
		t.Error("expected nil for unrecognized format")
	}
	if ParseUserID("") != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseUserID_JSONMissingDeviceID(t *testing.T) {
	t.Parallel()
	raw := `{"session_id":"sess-uuid"}`
	if ParseUserID(raw) != nil {
		t.Error("expected nil when device_id missing")
	}
}

// --- compareVersions tests ---

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"2.1.78", "2.1.78", 0},
		{"2.1.79", "2.1.78", 1},
		{"2.1.77", "2.1.78", -1},
		{"2.2.0", "2.1.78", 1},
		{"3.0.0", "2.1.78", 1},
		{"1.9.99", "2.0.0", -1},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
