package disguise

import (
	"regexp"
	"strings"
)

// ccVersionInBillingRe matches the semver triple portion of cc_version
// (X.Y.Z) ONLY. It deliberately does not capture the trailing 3-char
// message-derived suffix (".abc"), because we no longer rewrite that suffix
// — it is preserved verbatim from whatever the client originally sent.
//
// This is the same regex sub2api uses in its gateway_billing_header.go
// (see commit e51c9e50 in the sub2api repo).
var ccVersionInBillingRe = regexp.MustCompile(`cc_version=\d+\.\d+\.\d+`)

// billingHeaderPrefix is the marker that identifies a system block carrying
// the x-anthropic-billing-header metadata. Only blocks whose text starts
// with this prefix are touched — user content is left alone even if it
// happens to contain a "cc_version=..." substring.
const billingHeaderPrefix = "x-anthropic-billing-header"

// syncBillingHeaderVersion rewrites the X.Y.Z portion of cc_version inside
// any x-anthropic-billing-header system block, replacing it with the
// version embedded in the fingerprint UA. The 3-char message-derived suffix
// (.abc) and every other field (cc_entrypoint, cch, cc_workload, …) are
// preserved byte-for-byte from whatever the client sent.
//
// Why we do not compute the suffix ourselves:
//
// The suffix is produced by a SHA256-based algorithm on the client side
// whose exact form (salt and character indices) we cannot reliably
// replicate. We previously shipped an implementation derived from
// auth2api's reference, but the BillingHeaderObserver observed deterministic
// mismatches starting with Claude CLI 2.1.105 — meaning the algorithm has
// changed at least once since the reference was written. Emitting a wrong
// suffix is strictly worse than emitting a slightly outdated one: a fake
// suffix is a deterministic "this request did not come from a real CLI"
// signal, while leaving the client's real suffix in place produces, at
// worst, a "headers-vs-body" version drift that looks like a normal
// client mid-upgrade.
//
// Side effect: when the fingerprint UA version differs from the client
// CLI version, the resulting block has a triple from one version and a
// suffix from another. This is the same compromise sub2api makes — see
// gateway_billing_header.go in that repo.
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
// injectSystemPromptInPlace. That function may prepend a new system block
// which, if it happens to carry the billing header prefix, needs to be
// visible to this rewriter. The CC lightweight path has no system-prompt
// injection step, so the only ordering requirement there is "after body is
// parsed" — which is trivially true since we mutate parsed in place.
func syncBillingHeaderVersion(parsed map[string]interface{}, uaVersion string) {
	if uaVersion == "" || parsed == nil {
		return
	}
	replacement := "cc_version=" + uaVersion

	rewriteBlockText := func(text string) string {
		return ccVersionInBillingRe.ReplaceAllString(text, replacement)
	}

	system, ok := parsed["system"]
	if !ok {
		return
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
