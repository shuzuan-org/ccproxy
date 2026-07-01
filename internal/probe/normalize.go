package probe

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Normalize rewrites a JSON request body into a canonical form for
// differential comparison. It touches ONLY structure, never characters:
//
//   - object keys are sorted (Go's encoding/json already marshals map keys
//     sorted, so a round-trip through map[string]any canonicalizes ordering)
//   - dynamic fields that legitimately vary request-to-request (device/session
//     ids, uuids) are replaced with stable placeholders so they do not
//     masquerade as fingerprint drift
//
// Crucially it does NOT apply Unicode normalization (NFC/NFKC). NFKC would fold
// the homoglyph apostrophes (U+2019/U+02BC/U+02B9) back into a plain "'", which
// is precisely the signal we are hunting — normalizing it away would blind the
// diff. Character-level differences are left intact for Diff to discover.
//
// The returned string is deterministic for equivalent inputs: two bodies that
// differ only in key ordering or masked dynamic fields normalize to identical
// strings.
func Normalize(body []byte) (string, error) {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return "", err
	}
	masked := maskDynamic(v, nil)
	// Disable HTML escaping so <, >, & stay literal. This keeps placeholders
	// like "<masked>" readable and, more importantly, leaves the system-prompt
	// text byte-for-byte as emitted (no < noise) so the diff compares the
	// real characters — including any homoglyph carriers — directly.
	var sb strings.Builder
	enc := json.NewEncoder(&sb)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(masked); err != nil {
		return "", err
	}
	// Encoder.Encode appends a trailing newline; trim it for stable output.
	return strings.TrimRight(sb.String(), "\n"), nil
}

// uuidRe matches a canonical UUID anywhere in a string. Used to blank
// device/session identifiers that appear inside the stringified metadata.user_id.
var uuidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// hex64Re matches a 64-hex-char device_id token.
var hex64Re = regexp.MustCompile(`[0-9a-fA-F]{64}`)

// dynamicKeys are object keys whose *values* are per-request nonces and should
// be blanked wholesale regardless of shape.
var dynamicKeys = map[string]bool{
	"user_id":      true, // metadata.user_id (device_id + session_id blob)
	"session_id":   true,
	"device_id":    true,
	"account_uuid": true,
	"request_id":   true,
	"idempotency":  true,
}

// maskDynamic walks the decoded JSON, replacing dynamic fields with stable
// placeholders. path is the key path used to decide masking (unused for now
// beyond depth, kept for future field-scoped rules).
func maskDynamic(v any, path []string) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if dynamicKeys[k] {
				out[k] = "<masked>"
				continue
			}
			out[k] = maskDynamic(val, append(path, k))
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = maskDynamic(e, path)
		}
		return out
	case string:
		return maskStringTokens(t)
	default:
		return v
	}
}

// maskStringTokens blanks uuid/hex64 tokens embedded inside string values
// (e.g. the stringified metadata.user_id JSON, or an id spliced into text),
// without disturbing surrounding characters. This is a token substitution, not
// Unicode normalization — homoglyphs and other characters pass through
// untouched.
func maskStringTokens(s string) string {
	s = uuidRe.ReplaceAllString(s, "<uuid>")
	s = hex64Re.ReplaceAllString(s, "<hex64>")
	return s
}

// SystemText extracts and concatenates the textual content of the request's
// system prompt. Anthropic bodies carry system as either a plain string or a
// list of {type:"text", text:"..."} blocks. This is the region where covert
// template fingerprints live, so the runner scans and diffs it directly rather
// than the whole body (which is dominated by tools/messages noise).
//
// It returns the joined text and true if a system field was present.
func SystemText(body []byte) (string, bool) {
	var parsed struct {
		System json.RawMessage `json:"system"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || len(parsed.System) == 0 {
		return "", false
	}
	// Try plain string first.
	var s string
	if json.Unmarshal(parsed.System, &s) == nil {
		return s, true
	}
	// Else a list of blocks.
	var blocks []map[string]any
	if json.Unmarshal(parsed.System, &blocks) != nil {
		return "", false
	}
	var sb strings.Builder
	for _, b := range blocks {
		if txt, ok := b["text"].(string); ok {
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(txt)
		}
	}
	return sb.String(), true
}

// sortedKeys is a small helper for deterministic iteration in tests/reports.
func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// dateLineRe matches the observed date-injection line ("Today<apostrophe>s
// date is <date>."). The apostrophe is `.` so any homoglyph variant matches;
// the date accepts both '-' and '/' separators. Anchored to a line so it
// pinpoints the carrier regardless of which field it lives in.
var dateLineRe = regexp.MustCompile(`Today.s date is [0-9]{4}[-/][0-9]{2}[-/][0-9]{2}\.`)

// collectTemplateStrings walks the decoded body and returns every string value
// that is part of the prompt template (system blocks and message content text),
// excluding obviously dynamic id fields. This is the region a covert template
// fingerprint can hide in — the observed 2.1.197 build injects its date line
// into a <system-reminder> inside messages[], NOT into system[], so scanning
// only system[] would miss it.
func collectTemplateStrings(body []byte) []string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return nil
	}
	var out []string
	var walk func(any)
	walk = func(n any) {
		switch t := n.(type) {
		case map[string]any:
			for k, val := range t {
				if dynamicKeys[k] {
					continue
				}
				walk(val)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		case string:
			out = append(out, t)
		}
	}
	walk(v)
	return out
}

// DateLine locates the covert date-injection line anywhere in the request body
// (system blocks or message reminders) and returns it verbatim — including its
// exact apostrophe code point and date separator, the two known carrier slots.
// Returns "" if no such line is present.
func DateLine(body []byte) string {
	for _, s := range collectTemplateStrings(body) {
		if m := dateLineRe.FindString(s); m != "" {
			return m
		}
	}
	return ""
}
