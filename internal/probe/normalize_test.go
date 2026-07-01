package probe

import (
	"strings"
	"testing"
)

func TestNormalize_KeyOrderCanonical(t *testing.T) {
	a := []byte(`{"model":"x","stream":true,"max_tokens":10}`)
	b := []byte(`{"max_tokens":10,"stream":true,"model":"x"}`)
	na, err := Normalize(a)
	if err != nil {
		t.Fatal(err)
	}
	nb, err := Normalize(b)
	if err != nil {
		t.Fatal(err)
	}
	if na != nb {
		t.Fatalf("key-reordered bodies should normalize equal:\n a=%s\n b=%s", na, nb)
	}
}

func TestNormalize_MasksDynamicFields(t *testing.T) {
	body := []byte(`{"metadata":{"user_id":"{\"device_id\":\"abc\",\"session_id\":\"9abcdef0-1234-4abc-8def-aabbccddeeff\"}"},"model":"x"}`)
	out, err := Normalize(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "<masked>") {
		t.Errorf("user_id should be masked, got: %s", out)
	}
	if strings.Contains(out, "9abcdef0-1234") {
		t.Errorf("session uuid must not survive normalization, got: %s", out)
	}
}

func TestNormalize_TwoRequestsDifferingOnlyInIDs_Equal(t *testing.T) {
	// Same semantic request, different per-request ids => must normalize equal
	// so the ids don't masquerade as fingerprint drift.
	a := []byte(`{"model":"x","metadata":{"user_id":"sess-11111111-1111-4111-8111-111111111111"}}`)
	b := []byte(`{"model":"x","metadata":{"user_id":"sess-22222222-2222-4222-8222-222222222222"}}`)
	na, _ := Normalize(a)
	nb, _ := Normalize(b)
	if na != nb {
		t.Fatalf("bodies differing only in ids should normalize equal:\n a=%s\n b=%s", na, nb)
	}
}

func TestNormalize_PreservesHomoglyph(t *testing.T) {
	// THE critical guard: normalization must NOT fold the homoglyph apostrophe
	// away, or the diff layer goes blind. U+2019 must survive verbatim.
	body := []byte(`{"system":"Today’s date is 2026-07-01."}`)
	out, err := Normalize(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.ContainsRune(out, 0x2019) {
		t.Fatalf("homoglyph U+2019 must survive normalization, got: %q", out)
	}
	if strings.Contains(out, "Today's") {
		t.Fatalf("normalization must not have folded U+2019 into ASCII ': %q", out)
	}
}

func TestSystemText_StringForm(t *testing.T) {
	body := []byte(`{"system":"Today's date is 2026-07-01."}`)
	got, ok := SystemText(body)
	if !ok || got != "Today's date is 2026-07-01." {
		t.Fatalf("SystemText(string) = %q,%v", got, ok)
	}
}

func TestSystemText_BlockListForm(t *testing.T) {
	body := []byte(`{"system":[{"type":"text","text":"You are Claude."},{"type":"text","text":"Today's date is 2026-07-01."}]}`)
	got, ok := SystemText(body)
	if !ok {
		t.Fatal("expected system present")
	}
	if !strings.Contains(got, "Today's date is 2026-07-01.") {
		t.Fatalf("joined system text missing date line: %q", got)
	}
	if !strings.Contains(got, "You are Claude.") {
		t.Fatalf("joined system text missing first block: %q", got)
	}
}

func TestSystemText_Absent(t *testing.T) {
	body := []byte(`{"model":"x"}`)
	if _, ok := SystemText(body); ok {
		t.Fatal("expected system absent")
	}
}

func TestDateLine_FindsInMessageReminder(t *testing.T) {
	// 2.1.197 shape: the date line lives in a <system-reminder> inside
	// messages[], not in system[]. DateLine must find it there.
	body := []byte(`{"system":[{"type":"text","text":"You are Claude."}],` +
		`"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>\nToday's date is 2026-07-01.\n</system-reminder>"}]}]}`)
	got := DateLine(body)
	if got != "Today's date is 2026-07-01." {
		t.Fatalf("DateLine = %q, want the reminder date line", got)
	}
}

func TestDateLine_MatchesHomoglyphAndSlashDate(t *testing.T) {
	body := []byte(`{"system":"Today` + "’" + `s date is 2026/07/01."}`)
	got := DateLine(body)
	if got == "" {
		t.Fatal("DateLine should match homoglyph apostrophe + slash date")
	}
	if !strings.ContainsRune(got, 0x2019) || !strings.Contains(got, "2026/07/01") {
		t.Fatalf("DateLine = %q, want homoglyph + slash preserved", got)
	}
}

func TestDateLine_AbsentReturnsEmpty(t *testing.T) {
	body := []byte(`{"system":"no date here","messages":[]}`)
	if got := DateLine(body); got != "" {
		t.Fatalf("DateLine = %q, want empty", got)
	}
}
