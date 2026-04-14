package disguise

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// Claude Code's cc_version=X.Y.Z.abc fingerprint algorithm — exact replica of
// the client-side utils/fingerprint.ts, cross-checked against
// ../auth2api/src/proxy/cloaking.ts:computeFingerprint. The 3-char suffix
// is SHA256(SALT + msg[4] + msg[7] + msg[20] + version)[:3] where msg is
// the first user message's text (or "0" for missing positions).
//
// The salt and indices must match what Anthropic's server-side validator
// expects — if upstream ever recomputes this to check the request, any
// deviation is a deterministic detection signal. Do NOT edit these constants
// unless you've confirmed the upstream algorithm has changed.
const (
	billingFingerprintSalt = "59cf53e54c78"
)

var billingFingerprintCharIndices = [...]int{4, 7, 20}

// ccVersionInBillingRe captures the entire cc_version=X.Y.Z[.abc] segment
// and its components. Group 1 is the semver triple, group 2 (optional) is
// the 3-char fingerprint suffix. Used for both matching (is this block a
// billing header?) and parsing (what version did the client send?).
var ccVersionInBillingRe = regexp.MustCompile(`cc_version=(\d+)\.(\d+)\.(\d+)(?:\.([A-Za-z0-9]{3}))?`)

// billingHeaderPrefix is the marker that identifies a system block carrying
// the x-anthropic-billing-header metadata. Only blocks whose text starts
// with this prefix are touched — user content is left alone even if it
// happens to contain a "cc_version=..." substring.
const billingHeaderPrefix = "x-anthropic-billing-header"

// computeBillingFingerprint mirrors Claude Code's utils/fingerprint.ts:
//
//	SHA256(SALT + msg[4] + msg[7] + msg[20] + version).slice(0, 3)
//
// where msg is the first user message's text (or "0" for any out-of-range
// index). The 3-char suffix is lowercase hex. messageText may be empty, in
// which case all three chars are "0".
func computeBillingFingerprint(messageText, version string) string {
	var chars [len(billingFingerprintCharIndices)]byte
	for i, idx := range billingFingerprintCharIndices {
		if idx < len(messageText) {
			chars[i] = messageText[idx]
		} else {
			chars[i] = '0'
		}
	}
	var sb strings.Builder
	sb.Grow(len(billingFingerprintSalt) + len(chars) + len(version))
	sb.WriteString(billingFingerprintSalt)
	sb.Write(chars[:])
	sb.WriteString(version)
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])[:3]
}

// extractFirstUserMessageText returns the text content of the first message
// with role=user. Matches Claude Code's extractFirstUserMessageText:
//   - string content → return as-is
//   - array content → return the first {type:"text"} block's text
//   - anything else → return ""
func extractFirstUserMessageText(parsed map[string]interface{}) string {
	messages, ok := parsed["messages"].([]interface{})
	if !ok {
		return ""
	}
	for _, raw := range messages {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		if role != "user" {
			continue
		}
		switch content := m["content"].(type) {
		case string:
			return content
		case []interface{}:
			for _, b := range content {
				block, ok := b.(map[string]interface{})
				if !ok {
					continue
				}
				if t, _ := block["type"].(string); t == "text" {
					if text, ok := block["text"].(string); ok {
						return text
					}
				}
			}
		}
		// First user message consumed — don't look further.
		return ""
	}
	return ""
}

// parseSemverTriple parses "X.Y.Z" into a semver struct. Returns an invalid
// semver{} on any parse failure. Only the major.minor.patch portion is
// consumed — trailing content (like ".abc" fingerprint suffix) is ignored.
func parseSemverTriple(maj, min, pat string) semver {
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	c, err3 := strconv.Atoi(pat)
	if err1 != nil || err2 != nil || err3 != nil {
		return semver{}
	}
	return semver{major: a, minor: b, patch: c, valid: true}
}

// syncBillingHeaderVersion conditionally rewrites cc_version=X.Y.Z.abc inside
// billing-header system blocks, upgrading old client versions to match the
// fingerprint UA version we send upstream.
//
// Upgrade rule: a block's cc_version is rewritten ONLY when its semver triple
// is STRICTLY OLDER than uaVersion. In that case both the triple and the
// 3-char fingerprint suffix are recomputed via computeBillingFingerprint so
// the result is self-consistent at uaVersion. When the client's cc_version
// is equal or newer, the block is passed through untouched — this trusts
// the client's own (real) fingerprint and avoids damage from any tiny drift
// between our replicated algorithm and upstream's. The only cost of trust
// is a request whose UA claims fp-version while its body claims a newer
// version; that's a real (rare) situation where we lag the CLI release, and
// the trade-off is deliberate.
//
// Other fields of the billing header (cc_entrypoint, cch, cc_workload, …)
// are preserved byte-for-byte.
//
// This is a no-op when:
//   - uaVersion is empty or unparseable,
//   - parsed is nil,
//   - parsed has no "system" field,
//   - "system" is not a string or array of objects,
//   - no system block carries the billing header prefix,
//   - every billing block's cc_version is already >= uaVersion.
//
// Mutates parsed in place. Callers marshal parsed once after all body
// transforms are complete.
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
	targetVer := parseVersion(uaVersion)
	if !targetVer.valid {
		return
	}

	// Lazy: only extract message text when we're about to rewrite. Most
	// requests from modern clients will skip the upgrade entirely, so we
	// don't want to pay the walk cost on every call.
	var msgText string
	var msgTextLoaded bool
	getMsgText := func() string {
		if !msgTextLoaded {
			msgText = extractFirstUserMessageText(parsed)
			msgTextLoaded = true
		}
		return msgText
	}

	rewriteBlockText := func(text string) string {
		return ccVersionInBillingRe.ReplaceAllStringFunc(text, func(match string) string {
			sub := ccVersionInBillingRe.FindStringSubmatch(match)
			// sub[1..3] = major, minor, patch; sub[4] = optional suffix.
			clientVer := parseSemverTriple(sub[1], sub[2], sub[3])
			if clientVer.valid && !isNewerVersion(targetVer, clientVer) {
				// Client is already at (or above) the fp UA version — trust
				// its original value, including its real-algorithm suffix.
				return match
			}
			// Upgrade: rewrite both the semver triple and the suffix so the
			// result is self-consistent at uaVersion.
			suffix := computeBillingFingerprint(getMsgText(), uaVersion)
			return "cc_version=" + uaVersion + "." + suffix
		})
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
