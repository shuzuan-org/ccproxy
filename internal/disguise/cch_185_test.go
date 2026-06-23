package disguise

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Hermetic test vectors. Expected cch values were produced by the
// independently-verified reference implementation
// mitm-analysis/cch-probe/cch_compute_185.py (XXH64(normalize(body),
// seed=ATTEST_V3) & 0xFFFFF). These bodies contain no real prompt data,
// so they live in the test and run in CI.
var cch185SyntheticVectors = []struct {
	name string
	body string
	want string
}{
	{
		name: "full_body_with_max_tokens",
		body: `{"model":"claude-opus-4-8","messages":[{"role":"user","content":[{"type":"text","text":"hello world test body"}]}],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.185.7d9; cc_entrypoint=cli; cch=00000;"}],"metadata":{"user_id":"abc"},"max_tokens":32000,"thinking":{"type":"disabled"},"stream":true}`,
		want: "3834b",
	},
	{
		name: "max_tokens_early",
		body: `{"model":"claude-haiku-4-5","max_tokens":100,"messages":[],"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.185.abc; cc_entrypoint=cli; cch=00000;"}]}`,
		want: "96d12",
	},
}

func TestComputeCCH185_SyntheticVectors(t *testing.T) {
	for _, tc := range cch185SyntheticVectors {
		t.Run(tc.name, func(t *testing.T) {
			got := ComputeCCH185([]byte(tc.body))
			if got != tc.want {
				t.Errorf("ComputeCCH185 = %s, want %s (must match cch_compute_185.py)", got, tc.want)
			}
		})
	}
}

func TestNormalizeBodyForCCH185(t *testing.T) {
	in := `{"model":"claude-opus-4-8","x":1,"max_tokens":32000,"y":2}`
	want := `{"model":"","x":1,"y":2}`
	got := string(normalizeBodyForCCH185([]byte(in)))
	if got != want {
		t.Errorf("normalize = %q, want %q", got, want)
	}
	// Input must not be mutated.
	if in != `{"model":"claude-opus-4-8","x":1,"max_tokens":32000,"y":2}` {
		t.Error("normalizeBodyForCCH185 mutated its input")
	}
}

// TestCCH185_GroundTruth verifies against the real captured wire bodies
// when present. These files hold real prompt content (gitignored), so the
// test skips when they are absent (CI, fresh checkout).
func TestCCH185_GroundTruth(t *testing.T) {
	cchRe := regexp.MustCompile(`cch=[0-9a-f]{5}`)
	cases := []struct {
		file string
		want string
	}{
		{"20260622-015610-063.pre", "4eb53"},
		{"20260622-015610-064.pre", "a63f5"},
	}
	dir := filepath.Join("..", "..", "mitm-analysis", "cch-probe", "captured")
	for _, c := range cases {
		raw, err := os.ReadFile(filepath.Join(dir, c.file))
		if err != nil {
			t.Skipf("ground-truth %s absent (%v) — skipping", c.file, err)
			return
		}
		// Captured body carries the REAL cch; the hash input uses the
		// cch=00000 placeholder. Reset it before computing.
		body := cchRe.ReplaceAll(raw, []byte("cch=00000"))
		if got := ComputeCCH185(body); got != c.want {
			t.Errorf("%s: ComputeCCH185 = %s, want %s", c.file, got, c.want)
		}
	}
}

// TestCCHDispatch_185IsActive confirms the whitelist head selects the new
// algorithm, and that rewriteCCHInBody routes through it.
func TestCCHDispatch_185IsActive(t *testing.T) {
	if latestValidatedTuple().CCHVariant != cchVariantXXH64Norm {
		t.Fatalf("whitelist head CCHVariant = %d, want cchVariantXXH64Norm (%d)",
			latestValidatedTuple().CCHVariant, cchVariantXXH64Norm)
	}
	body := []byte(cch185SyntheticVectors[0].body)
	if !rewriteCCHInBody(body) {
		t.Fatal("rewriteCCHInBody returned false (no placeholder found)")
	}
	idx := indexOf(body, []byte("cch="))
	got := string(body[idx+4 : idx+9])
	if got != cch185SyntheticVectors[0].want {
		t.Errorf("rewriteCCHInBody wrote cch=%s, want %s (should use ComputeCCH185)",
			got, cch185SyntheticVectors[0].want)
	}
}
