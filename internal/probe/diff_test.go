package probe

import "testing"

func TestDiff_Identical_NoHunks(t *testing.T) {
	s := `{"system":"Today's date is 2026-07-01."}`
	if h := Diff(s, s); len(h) != 0 {
		t.Fatalf("identical strings should diff clean, got %+v", h)
	}
}

func TestDiff_ApostropheSubstitution(t *testing.T) {
	// The core scenario: same semantic content, one apostrophe swapped for its
	// homoglyph. A line diff would show these as identical; the rune diff must
	// pinpoint the single position.
	base := "Today's date is 2026-07-01."
	variant := "Today’s date is 2026-07-01."
	hunks := Diff(base, variant)
	if len(hunks) != 1 {
		t.Fatalf("expected exactly 1 hunk, got %d: %+v", len(hunks), hunks)
	}
	h := hunks[0]
	if h.RuneIndex != 5 {
		t.Errorf("rune index = %d, want 5", h.RuneIndex)
	}
	if h.Base != '\'' || h.Variant != 0x2019 {
		t.Errorf("hunk = base %U variant %U, want ' -> U+2019", h.Base, h.Variant)
	}
	if h.BaseCP != "U+0027" || h.VariantCP != "U+2019" {
		t.Errorf("code points = %s -> %s, want U+0027 -> U+2019", h.BaseCP, h.VariantCP)
	}
}

func TestDiff_DateSeparatorSubstitution(t *testing.T) {
	// The cnTZ signal: '-' -> '/'. Two positions differ (month and day seps).
	base := "date is 2026-07-01."
	variant := "date is 2026/07/01."
	hunks := Diff(base, variant)
	if len(hunks) != 2 {
		t.Fatalf("expected 2 hunks (both separators), got %d: %+v", len(hunks), hunks)
	}
	for _, h := range hunks {
		if h.Base != '-' || h.Variant != '/' {
			t.Errorf("hunk %+v, want - -> /", h)
		}
	}
}

func TestDiff_LengthMismatch_TailReported(t *testing.T) {
	base := "abc"
	variant := "abcd"
	hunks := Diff(base, variant)
	if len(hunks) != 1 {
		t.Fatalf("expected 1 tail hunk, got %d: %+v", len(hunks), hunks)
	}
	h := hunks[0]
	if h.Base != 0 || h.Variant != 'd' {
		t.Errorf("tail hunk = %U -> %U, want ∅ -> d", h.Base, h.Variant)
	}
	if h.BaseCP != "∅" {
		t.Errorf("base code point = %q, want ∅", h.BaseCP)
	}
}
