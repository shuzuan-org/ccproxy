package disguise

import (
	"strings"
	"testing"
)

func TestNormalizeDateLine_HomoglyphApostrophe(t *testing.T) {
	variants := []rune{0x2019, 0x2018, 0x02BC, 0x02B9, 0x2032}
	for _, r := range variants {
		in := "Today" + string(r) + "s date is 2026-07-01."
		out, changed := normalizeDateLine(in)
		if !changed {
			t.Errorf("rune %U: expected change", r)
		}
		if out != "Today's date is 2026-07-01." {
			t.Errorf("rune %U: got %q, want clean ASCII apostrophe", r, out)
		}
	}
}

func TestNormalizeDateLine_SlashSeparator(t *testing.T) {
	out, changed := normalizeDateLine("Today's date is 2026/07/01.")
	if !changed {
		t.Fatal("expected change for slash date")
	}
	if out != "Today's date is 2026-07-01." {
		t.Fatalf("got %q, want '-' separators", out)
	}
}

func TestNormalizeDateLine_BothCarriers(t *testing.T) {
	out, changed := normalizeDateLine("Today’s date is 2026/07/01.")
	if !changed || out != "Today's date is 2026-07-01." {
		t.Fatalf("got %q changed=%v, want fully clean", out, changed)
	}
}

func TestNormalizeDateLine_AlreadyClean_NoChange(t *testing.T) {
	in := "Today's date is 2026-07-01."
	out, changed := normalizeDateLine(in)
	if changed || out != in {
		t.Fatalf("clean line must be untouched: got %q changed=%v", out, changed)
	}
}

func TestNormalizeDateLine_DoesNotTouchOtherText(t *testing.T) {
	// A curly apostrophe elsewhere in the string (user prompt) must survive;
	// only the date-line span is normalized.
	in := "The user’s file is ready. Today’s date is 2026/07/01. Don’t touch this ’."
	out, _ := normalizeDateLine(in)
	if !strings.Contains(out, "Today's date is 2026-07-01.") {
		t.Errorf("date line not normalized: %q", out)
	}
	if !strings.Contains(out, "The user’s file") {
		t.Errorf("user text before the date line must be untouched: %q", out)
	}
	if !strings.Contains(out, "Don’t touch this ’.") {
		t.Errorf("user text after the date line must be untouched: %q", out)
	}
}

func TestNormalizeDateLine_NoDateLine(t *testing.T) {
	in := "There is no date here, just a curly ’ apostrophe."
	out, changed := normalizeDateLine(in)
	if changed || out != in {
		t.Fatalf("string without date line must be untouched: %q changed=%v", out, changed)
	}
}

func TestRewriteDateFingerprint_SystemString(t *testing.T) {
	parsed := map[string]interface{}{
		"system": "You are Claude.\nToday’s date is 2026/07/01.",
	}
	if !rewriteDateFingerprintInPlace(parsed) {
		t.Fatal("expected change")
	}
	got := parsed["system"].(string)
	if !strings.Contains(got, "Today's date is 2026-07-01.") {
		t.Fatalf("system string not normalized: %q", got)
	}
}

func TestRewriteDateFingerprint_SystemBlockList(t *testing.T) {
	parsed := map[string]interface{}{
		"system": []interface{}{
			map[string]interface{}{"type": "text", "text": "You are Claude."},
			map[string]interface{}{"type": "text", "text": "Today’s date is 2026-07-01."},
		},
	}
	if !rewriteDateFingerprintInPlace(parsed) {
		t.Fatal("expected change")
	}
	blocks := parsed["system"].([]interface{})
	got := blocks[1].(map[string]interface{})["text"].(string)
	if got != "Today's date is 2026-07-01." {
		t.Fatalf("block text not normalized: %q", got)
	}
}

func TestRewriteDateFingerprint_MessagesReminder(t *testing.T) {
	// 2.1.197 shape: carrier lives in a <system-reminder> inside messages[].
	parsed := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type": "text",
						"text": "<system-reminder>\nToday’s date is 2026/07/01.\n</system-reminder>",
					},
				},
			},
		},
	}
	if !rewriteDateFingerprintInPlace(parsed) {
		t.Fatal("expected change in messages reminder")
	}
	msg := parsed["messages"].([]interface{})[0].(map[string]interface{})
	block := msg["content"].([]interface{})[0].(map[string]interface{})
	got := block["text"].(string)
	if !strings.Contains(got, "Today's date is 2026-07-01.") {
		t.Fatalf("reminder date line not normalized: %q", got)
	}
	if strings.ContainsRune(got, 0x2019) || strings.Contains(got, "2026/07/01") {
		t.Fatalf("carrier chars survived: %q", got)
	}
}

func TestRewriteDateFingerprint_MessageContentString(t *testing.T) {
	parsed := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": "Today’s date is 2026-07-01.",
			},
		},
	}
	if !rewriteDateFingerprintInPlace(parsed) {
		t.Fatal("expected change in string content")
	}
	got := parsed["messages"].([]interface{})[0].(map[string]interface{})["content"].(string)
	if got != "Today's date is 2026-07-01." {
		t.Fatalf("string content not normalized: %q", got)
	}
}

func TestRewriteDateFingerprint_NoCarrier_NoChange(t *testing.T) {
	parsed := map[string]interface{}{
		"system":   "You are Claude. The user’s request is important.",
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "hello ’world’"}},
	}
	if rewriteDateFingerprintInPlace(parsed) {
		t.Fatal("no date line present — must report no change and leave curly quotes alone")
	}
	if parsed["system"].(string) != "You are Claude. The user’s request is important." {
		t.Error("system text with legitimate curly apostrophe was altered")
	}
}

func TestRewriteDateFingerprint_NilSafe(t *testing.T) {
	if rewriteDateFingerprintInPlace(nil) {
		t.Fatal("nil must be a no-op")
	}
}

func TestNormalizeDateLine_MultipleOccurrences(t *testing.T) {
	// Two carrier lines in one string (e.g. compacted history quoting an
	// earlier reminder) — BOTH must be cleaned, not just the first.
	in := "First: Today’s date is 2026/07/01.\n...later...\nAgain: Today’s date is 2026/07/01."
	out, changed := normalizeDateLine(in)
	if !changed {
		t.Fatal("expected change")
	}
	if strings.ContainsRune(out, 0x2019) || strings.Contains(out, "2026/07/01") {
		t.Fatalf("all occurrences must be cleaned, got: %q", out)
	}
	if strings.Count(out, "Today's date is 2026-07-01.") != 2 {
		t.Fatalf("expected 2 cleaned lines, got: %q", out)
	}
}

func TestNormalizeDateLine_MixedCleanAndDirty(t *testing.T) {
	// First occurrence already clean, second dirty — must still clean the
	// second and report changed.
	in := "Today's date is 2026-07-01. ... Today’s date is 2026/07/01."
	out, changed := normalizeDateLine(in)
	if !changed {
		t.Fatal("expected change from the dirty second occurrence")
	}
	if strings.ContainsRune(out, 0x2019) || strings.Contains(out, "2026/07/01") {
		t.Fatalf("dirty occurrence not cleaned: %q", out)
	}
}
