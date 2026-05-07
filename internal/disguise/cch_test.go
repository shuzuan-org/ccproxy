package disguise

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// xxhash64Seed wraps xxhash64Keyed with seed-derived initial values.
// Used only in tests to validate the round/merge logic against published
// xxhash64 reference vectors.
func xxhash64Seed(body []byte, seed uint64) uint64 {
	v1 := seed + prime64_1 + prime64_2
	v2 := seed + prime64_2
	v3 := seed
	v4 := seed - prime64_1
	return xxhash64Keyed(body, v1, v2, v3, v4)
}

func TestXxhash64StandardVectors(t *testing.T) {
	// Reference values for standard xxhash64 with seed=0. If any of these
	// fail, the round/merge/avalanche steps are broken and the keyed
	// implementation cannot be trusted either.
	cases := []struct {
		name string
		in   []byte
		want uint64
	}{
		{"empty", []byte(""), 0xef46db3751d8e999},
		{"abc", []byte("abc"), 0x44bc2cf5ad770999},
		{"32-a", bytes.Repeat([]byte("a"), 32), 0x856e843298f99ad7},
		{"hello world", []byte("hello world"), 0x45ab6734b21e6968},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := xxhash64Seed(tc.in, 0)
			if got != tc.want {
				t.Errorf("xxhash64Seed(%q) = 0x%016x, want 0x%016x", tc.in, got, tc.want)
			}
		})
	}
}

// TestComputeCCH_RealSample verifies that the keyed xxhash64 implementation
// reproduces a real cch from a Claude Code 2.1.126 client request captured
// via mitmdump.
func TestComputeCCH_RealSample(t *testing.T) {
	path := filepath.Join("..", "..", "mitm-analysis", "cch-probe", "fresh_sample.bin")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("ground-truth sample missing: %v", err)
	}
	// The sample was captured AFTER cch was written; reconstruct the
	// pre-write body by replacing "cch=58e37" back to "cch=00000".
	const observedCCH = "58e37"
	pre := bytes.Replace(body, []byte("cch="+observedCCH), []byte("cch=00000"), 1)
	got := ComputeCCH(pre)
	if got != observedCCH {
		t.Errorf("ComputeCCH(fresh_sample.bin) = %s, want %s", got, observedCCH)
	}
}

func TestRewriteCCHInBody_Roundtrip(t *testing.T) {
	body := []byte("prefix; cch=00000; suffix")
	if !rewriteCCHInBody(body) {
		t.Fatal("rewriteCCHInBody returned false on body with placeholder")
	}
	// The 5 chars must be hex now (and not all zeros — only 1/2^20 chance).
	got := string(body[len("prefix; cch="):len("prefix; cch=")+5])
	if len(got) != 5 {
		t.Fatalf("rewritten cch length = %d, want 5", len(got))
	}
	for _, c := range got {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("rewritten cch %q contains non-hex char %q", got, c)
		}
	}
	// Re-computing on the rewritten body should NOT match the embedded
	// value (because the body changed when we wrote it).
	if reHash := ComputeCCH(body); reHash == got {
		t.Errorf("expected hash drift after in-place rewrite, but ComputeCCH = embedded = %s", reHash)
	}
}

func TestRewriteCCHInBody_NoPlaceholder(t *testing.T) {
	body := []byte("no cch here at all")
	if rewriteCCHInBody(body) {
		t.Errorf("rewriteCCHInBody returned true on body without placeholder")
	}
}

func TestRewriteCCHInBody_FirstOccurrenceOnly(t *testing.T) {
	body := []byte("cch=00000; and again cch=00000;")
	rewriteCCHInBody(body)
	// First placeholder gets the real value; second remains "00000"
	// because indexOf returns the first match and rewriteCCHInBody only
	// rewrites that one occurrence. (The Bun-native implementation does
	// the same — it indexOf's once.)
	if !strings.Contains(string(body), "; and again cch=00000;") {
		t.Errorf("second placeholder unexpectedly modified: %s", body)
	}
}
