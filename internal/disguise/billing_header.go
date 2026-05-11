package disguise

import (
	"fmt"
	"regexp"
	"strings"
)

// ccVersionFullRe matches the full cc_version=X.Y.Z[.suffix] form. The
// triple is always present; an optional 3-char suffix follows. The suffix
// charset is intentionally any-non-delimiter (`[^;\s]`) rather than
// strictly hex — when the client sent a malformed/legacy/non-hex suffix
// (`.zzz`, `.qqq`), we still want to swallow it during the rewrite so it
// does not survive into the new cc_version. The recomputed suffix we
// inject is always a valid 3-hex value.
var ccVersionFullRe = regexp.MustCompile(`cc_version=\d+\.\d+\.\d+(?:\.[^;\s]{1,8})?`)

// cchFieldRe matches the cch=XXXXX field in a billing header block.
// The capture group is the 5-hex value (or "00000" placeholder).
var cchFieldRe = regexp.MustCompile(`cch=([0-9a-f]{5})`)

// billingHeaderPrefix is the marker that identifies a system block carrying
// the x-anthropic-billing-header metadata. Only blocks whose text starts
// with this prefix are touched — user content is left alone even if it
// happens to contain a "cc_version=..." substring.
const billingHeaderPrefix = "x-anthropic-billing-header"

// syncBillingHeaderVersion canonicalizes the x-anthropic-billing-header
// system block so that EVERY field we transmit is one we can verify
// ourselves. Specifically, on each billing block:
//
//  1. cc_version=X.Y.Z is rewritten to the current whitelist-head triple.
//     Any leading suffix (.abc) is consumed by the regex so it does not
//     survive into the new value — the suffix is recomputed in step 2.
//  2. The 3-hex suffix is recomputed using vM3 semantics (see three_hex.go)
//     against parsed.messages and the new triple, and appended:
//     cc_version=<uaVersion>.<3hex>. The client's old suffix was tied to
//     the old triple and is meaningless once we change the version.
//  3. The cch field is set to the "cch=00000;" placeholder. The actual
//     cch hash is computed AFTER json.Marshal because the input is the
//     entire serialized body — see rewriteCCHInBody in cch.go, called
//     by Engine.Apply at the end of the pipeline.
//
// History — the prior cognitive model has been REVERSED.
//
// Up to v0.1.12 ccproxy operated under "we cannot recompute the suffix
// reliably; the SHA256 replica drifted at 2.1.105+; emitting a wrong
// suffix is strictly worse than leaving the client's real one in place".
// That trade-off was correct given the information at the time — the
// "drift" was real, just misdiagnosed.
//
// Reverse-engineering the 2.1.126 binary on 2026-05-06 (see
// project_3hex_unreplicable.md and project_cch_algorithm_solved.md
// memories) showed the actual situation:
//
//   - cch is keyed-xxhash64 over the entire body, with hardcoded
//     ATTEST_KEYS that have stayed stable across 2.1.114 through 2.1.138
//     (verified by binary diff across 24 releases). It is fully
//     reproducible from wire bytes — see cch.go.
//
//   - The 3hex algorithm did not actually drift. What changed at 2.1.105
//     was the introduction of an isMeta filter that skips system-injected
//     `<system-reminder>` and similar wrappers when picking the "first
//     user message". The filter is reproducible from wire-visible text
//     prefixes — see three_hex.go isMetaTextPrefixes.
//
// With both algorithms now available locally, "leave the client value
// in place" stops being safer than "recompute". Once we change ANY byte
// of the body (UA, cc_version triple, metadata.user_id, …) the client's
// cch is invalid; the only choices are recompute correctly or emit a
// known-wrong cch. We recompute.
//
// Why we control cc_version explicitly (vs adopting client value):
//
//  cch verification depends on ATTEST_KEYS being valid for the version
//  we advertise. If a client reports a CLI version we have not
//  ground-truth-validated (could be older with rotated keys, could be
//  newer with rotated keys), our cch would not match what the server
//  expects. version_whitelist.go locks the triple to versions we know
//  produce correct cch + 3hex. See CLAUDE.md "Maintaining the cch /
//  3hex version whitelist" for the update procedure.
//
// Mutates parsed in place. Callers marshal parsed once after all body
// transforms are complete.
//
// No-op when:
//   - uaVersion is empty,
//   - parsed is nil,
//   - parsed has no "system" field,
//   - "system" is not a string or array of objects,
//   - no system block carries the billing header prefix.
//
// Call-order requirement (non-CC disguise path): must run AFTER
// injectSystemPromptInPlace and AFTER metadata.user_id rewriting, so the
// 3hex hashes the canonical first-user-message content.
func syncBillingHeaderVersion(parsed map[string]interface{}, uaVersion string) {
	if uaVersion == "" || parsed == nil {
		return
	}

	system, ok := parsed["system"]
	if !ok {
		return
	}

	// Compute the new 3-hex suffix once — same input regardless of how
	// many billing blocks happen to be present.
	messages, _ := parsed["messages"].([]interface{})
	threeHex := Compute3HexSuffix(uaVersion, messages)

	rewriteBlockText := func(text string) string {
		// Step 1+2: replace the entire cc_version=... match (triple +
		// optional suffix) with the canonicalized version.
		newCCVersion := fmt.Sprintf("cc_version=%s.%s", uaVersion, threeHex)
		text = ccVersionFullRe.ReplaceAllString(text, newCCVersion)

		// Step 3: cch placeholder. If a cch field already exists, reset
		// to "00000". Otherwise inject a new "cch=00000;" before the
		// trailing whitespace.
		if cchFieldRe.MatchString(text) {
			text = cchFieldRe.ReplaceAllString(text, "cch=00000")
		} else {
			text = appendCCHPlaceholder(text)
		}
		return text
	}

	switch v := system.(type) {
	case string:
		if !strings.HasPrefix(strings.TrimSpace(v), billingHeaderPrefix) {
			return
		}
		parsed["system"] = rewriteBlockText(v)

	case []interface{}:
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			text, ok := m["text"].(string)
			if !ok {
				continue
			}
			if !strings.HasPrefix(strings.TrimSpace(text), billingHeaderPrefix) {
				continue
			}
			m["text"] = rewriteBlockText(text)
		}
	}
}

// appendCCHPlaceholder appends "; cch=00000;" to a billing header text in
// a way that respects the existing trailing punctuation. Real Claude CLI
// formats the block as "field1=val1; field2=val2; cch=XXXXX;" — fields
// joined by "; " and a trailing ";". We follow that convention.
func appendCCHPlaceholder(text string) string {
	trimmed := strings.TrimRight(text, " \t\r\n")
	if !strings.HasSuffix(trimmed, ";") {
		trimmed += ";"
	}
	return trimmed + " cch=00000;"
}
