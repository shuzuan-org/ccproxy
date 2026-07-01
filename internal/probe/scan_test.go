package probe

import "testing"

func TestScanConfusables_PureASCII_NoFindings(t *testing.T) {
	// A clean template line as the official/first-party client would emit it.
	clean := "Today's date is 2026-07-01."
	got := ScanConfusables(clean)
	if len(got) != 0 {
		t.Fatalf("pure ASCII should yield no findings, got %d: %+v", len(got), got)
	}
}

func TestScanConfusables_ApostropheHomoglyph(t *testing.T) {
	// The exact carrier observed in 2.1.197 when known=true: U+2019.
	marked := "Today’s date is 2026-07-01."
	got := ScanConfusables(marked)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.Rune != 0x2019 {
		t.Errorf("rune = %U, want U+2019", f.Rune)
	}
	if f.CodePoint != "U+2019" {
		t.Errorf("code point = %q, want U+2019", f.CodePoint)
	}
	if f.LooksLike != '\'' {
		t.Errorf("looksLike = %q, want '", f.LooksLike)
	}
	if f.Category != "apostrophe" {
		t.Errorf("category = %q, want apostrophe", f.Category)
	}
	// The offending rune sits at "Today|’|s" => rune index 5.
	if f.RuneIndex != 5 {
		t.Errorf("rune index = %d, want 5", f.RuneIndex)
	}
}

func TestScanConfusables_AllApostropheVariants(t *testing.T) {
	// All four 2-bit encodings the observed fingerprint can emit; U+0027 is
	// clean (not flagged), the other three are flagged.
	cases := []struct {
		r       rune
		flagged bool
		cat     string
	}{
		{0x0027, false, ""},          // ' clean ASCII apostrophe
		{0x2019, true, "apostrophe"}, // ’
		{0x02BC, true, "apostrophe"}, // ʼ
		{0x02B9, true, "apostrophe"}, // ʹ
	}
	for _, c := range cases {
		s := "Today" + string(c.r) + "s date"
		got := ScanConfusables(s)
		if c.flagged {
			if len(got) != 1 {
				t.Errorf("rune %U: expected 1 finding, got %d", c.r, len(got))
				continue
			}
			if got[0].Category != c.cat {
				t.Errorf("rune %U: category = %q, want %q", c.r, got[0].Category, c.cat)
			}
		} else if len(got) != 0 {
			t.Errorf("rune %U: expected 0 findings (clean), got %d: %+v", c.r, len(got), got)
		}
	}
}

func TestScanConfusables_DateSeparatorNotFlagged(t *testing.T) {
	// The cnTZ signal swaps '-' for '/', but '/' is plain ASCII — the scanner
	// (a code-point layer) correctly does NOT flag it. That drift is caught by
	// the diff layer instead. This guards against over-flagging.
	s := "Today's date is 2026/07/01."
	if got := ScanConfusables(s); len(got) != 0 {
		t.Fatalf("'/' is ASCII and must not be flagged, got %+v", got)
	}
}

func TestScanConfusables_ZeroWidthAndBidi(t *testing.T) {
	s := "ab​cd‮ef" // zero-width space + right-to-left override
	got := ScanConfusables(s)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	if got[0].Category != "zero-width" || got[0].LooksLike != 0 {
		t.Errorf("first finding = %+v, want zero-width invisible", got[0])
	}
	if got[1].Category != "bidi" {
		t.Errorf("second finding category = %q, want bidi", got[1].Category)
	}
}

func TestScanConfusables_UnknownNonASCII_ReportedAsOther(t *testing.T) {
	// A novel carrier we didn't table must still surface, not be dropped.
	s := "he中llo" // a CJK char embedded
	got := ScanConfusables(s)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for unknown non-ASCII, got %d", len(got))
	}
	if got[0].Category != "other-nonascii" {
		t.Errorf("category = %q, want other-nonascii", got[0].Category)
	}
}

func TestScanConfusables_HyphenLookalike(t *testing.T) {
	s := "2026– 07" // en dash imitating hyphen
	got := ScanConfusables(s)
	if len(got) != 1 || got[0].Category != "hyphen" || got[0].LooksLike != '-' {
		t.Fatalf("expected hyphen finding, got %+v", got)
	}
}
