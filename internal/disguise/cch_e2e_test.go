package disguise

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// TestEndToEnd_BillingBlockSelfConsistent simulates the disguise pipeline's
// final two steps on a real Claude Code 2.1.126 request body:
//
//  1. syncBillingHeaderVersion mutates the parsed body (rewrites cc_version
//     triple, recomputes 3hex, injects/resets cch=00000 placeholder).
//  2. After json.Marshal, rewriteCCHInBody overwrites the placeholder with
//     the keyed-xxhash64 of the marshalled body.
//
// Invariant tested: re-hashing the final body (with cch reverted to
// "00000") must reproduce the cch we wrote. This proves the wire output
// is byte-level self-consistent — any server doing the same hash will
// validate it.
func TestEndToEnd_BillingBlockSelfConsistent(t *testing.T) {
	path := filepath.Join("..", "..", "mitm-analysis", "cch-probe", "fresh_sample.bin")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("ground-truth sample missing: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal sample: %v", err)
	}

	// Pretend our fingerprint UA version is 2.1.88 (the default ccproxy
	// fingerprint — older than the captured client to make the test
	// exercise a real triple change).
	const fpVersion = "2.1.88"
	syncBillingHeaderVersion(parsed, fpVersion)

	// Marshal — this is the wire body before cch is filled in.
	marshalled, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Final cch write.
	if !rewriteCCHInBody(marshalled) {
		t.Fatalf("rewriteCCHInBody returned false — placeholder missing?")
	}

	// Extract the cch we wrote.
	cchRe := regexp.MustCompile(`cch=([0-9a-f]{5})`)
	m := cchRe.FindSubmatch(marshalled)
	if m == nil {
		t.Fatalf("no cch field in final body")
	}
	writtenCCH := string(m[1])
	if writtenCCH == "00000" {
		t.Errorf("cch was not overwritten — still placeholder")
	}

	// Self-consistency check: revert to placeholder and recompute. The
	// answer must equal what we wrote.
	preBody := bytes.Replace(marshalled, []byte("cch="+writtenCCH), []byte("cch=00000"), 1)
	recomputed := ComputeCCH(preBody)
	if recomputed != writtenCCH {
		t.Errorf("body is NOT self-consistent: wrote cch=%s but ComputeCCH(reverted) = %s",
			writtenCCH, recomputed)
	}

	// Also confirm the cc_version triple was rewritten and a 3hex suffix
	// is present.
	cvRe := regexp.MustCompile(`cc_version=` + fpVersion + `\.([0-9a-f]{3})`)
	if !cvRe.Match(marshalled) {
		t.Errorf("cc_version=%s.<3hex> not found in final body", fpVersion)
	}
}
