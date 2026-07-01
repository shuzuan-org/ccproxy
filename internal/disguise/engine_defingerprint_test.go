package disguise

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestEngineApply_DefingerprintCleansAndCchCovers is the DoD test for the
// outbound date-fingerprint removal: it proves both that the covert carrier is
// normalized AND that the cch attestation is computed over the CLEANED body
// (not a stale value), which only holds if the de-fingerprint runs before the
// marshal+cch step inside Apply.
func TestEngineApply_DefingerprintCleansAndCchCovers(t *testing.T) {
	e := newTestEngine(t)

	origReq := newTestRequest(t, nil)
	origReq.Header.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	origReq.Header.Set("X-App", "cli")
	origReq.Header.Set("Anthropic-Beta", BetaClaudeCode)
	upstreamReq := newTestRequest(t, nil)

	validUserID := "user_" + strings.Repeat("a1", 32) + "_account__session_abc-123-def"
	// Carrier in a <system-reminder> inside messages[] (2.1.197 shape), with a
	// homoglyph apostrophe (U+2019) AND '/' date separators — the dirty form.
	reminder := "<system-reminder>\nToday’s date is 2026/07/01.\n</system-reminder>"
	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		// A billing block so cch has a placeholder to rewrite.
		"system": []interface{}{
			map[string]interface{}{
				"type": "text",
				"text": "x-anthropic-billing-header: cc_version=2.1.71.abc; cc_entrypoint=cli; cch=00000;",
			},
			map[string]interface{}{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
		},
		"metadata": map[string]interface{}{"user_id": validUserID},
		"messages": []interface{}{
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": reminder},
				},
			},
		},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1-id", "acct-1")
	if !applied {
		t.Fatal("expected applied=true for CC client")
	}

	// (1) The carrier must be normalized: clean apostrophe + '-' date.
	if !strings.Contains(string(outBody), "Today's date is 2026-07-01.") {
		t.Errorf("date line not normalized in output:\n%s", outBody)
	}
	if strings.ContainsRune(string(outBody), 0x2019) {
		t.Errorf("homoglyph apostrophe survived in output")
	}
	if strings.Contains(string(outBody), "2026/07/01") {
		t.Errorf("slash date separators survived in output")
	}

	// (2) DoD: the cch must cover the CLEANED body. rewriteCCHInBody hashes the
	// body while cch is the "00000" placeholder, then writes the digest in
	// place. So to verify, reset cch back to "00000" in the output and recompute
	// — it must equal the wire value. If de-fingerprint had run AFTER the cch
	// step, the wire cch would be the hash of the dirty body and this fails.
	cch := extractCch(t, outBody)
	if cch == "00000" {
		t.Fatal("cch placeholder was not rewritten")
	}
	reset := strings.Replace(string(outBody), "cch="+cch, "cch=00000", 1)
	var want string
	if latestValidatedTuple().CCHVariant == cchVariantXXH64Norm {
		want = ComputeCCH185([]byte(reset))
	} else {
		want = ComputeCCH([]byte(reset))
	}
	if cch != want {
		t.Errorf("cch=%s does not cover the cleaned body (want %s) — "+
			"de-fingerprint must run before the cch recompute", cch, want)
	}
}

func TestEngineApply_DefingerprintDisabled_LeavesFingerprint(t *testing.T) {
	e := newTestEngine(t)
	e.SetDefingerprint(false)

	origReq := newTestRequest(t, nil)
	origReq.Header.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	origReq.Header.Set("X-App", "cli")
	upstreamReq := newTestRequest(t, nil)

	reminder := "<system-reminder>\nToday’s date is 2026/07/01.\n</system-reminder>"
	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   "You are Claude Code, Anthropic's official CLI for Claude.",
		"metadata": map[string]interface{}{"user_id": "user_" + strings.Repeat("a1", 32) + "_account__session_x"},
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": []interface{}{map[string]interface{}{"type": "text", "text": reminder}},
			},
		},
	})

	outBody, _ := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1-id", "acct-1")
	// With de-fingerprint off, the carrier must survive untouched.
	if !strings.ContainsRune(string(outBody), 0x2019) || !strings.Contains(string(outBody), "2026/07/01") {
		t.Errorf("with defingerprint disabled the fingerprint must survive:\n%s", outBody)
	}
}

// extractCch pulls the cch=XXXXX value out of a body's billing block.
func extractCch(t *testing.T, body []byte) string {
	t.Helper()
	var parsed struct {
		System []struct {
			Text string `json:"text"`
		} `json:"system"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("unmarshal out body: %v", err)
	}
	for _, b := range parsed.System {
		if m := cchFieldRe.FindStringSubmatch(b.Text); m != nil {
			return m[1]
		}
	}
	t.Fatal("no cch field found in output body")
	return ""
}
