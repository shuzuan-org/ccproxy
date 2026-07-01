package proxy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRecordInboundBody_DisabledIsNoop(t *testing.T) {
	t.Setenv("CCPROXY_RECORD_DIR", "")
	// Should not panic or write anything; just returns.
	recordInboundBody([]byte(`{"x":1}`), "a")
}

func TestRecordInboundBody_WritesFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CCPROXY_RECORD_DIR", dir)
	recordInboundBody([]byte(`{"system":"Today's date is 2026-07-01."}`), "cn-side")

	matches, _ := filepath.Glob(filepath.Join(dir, "*.raw.json"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 recorded file, got %d", len(matches))
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"system":"Today's date is 2026-07-01."}` {
		t.Errorf("recorded body mismatch: %s", data)
	}
	// Label must be folded into the filename.
	if base := filepath.Base(matches[0]); !contains(base, "cn-side") {
		t.Errorf("filename %q should carry the label", base)
	}
}

func TestSanitizeLabel(t *testing.T) {
	cases := map[string]string{
		"a":         "a",
		"cn-side":   "cn-side",
		"us/side":   "us_side",
		"weird lbl": "weird_lbl",
		"":          "unknown",
	}
	for in, want := range cases {
		if got := sanitizeLabel(in); got != want {
			t.Errorf("sanitizeLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOfStr(s, sub) >= 0)
}
func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
