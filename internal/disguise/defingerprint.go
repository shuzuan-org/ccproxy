package disguise

import (
	"regexp"
	"strings"
)

// Covert date-line fingerprint removal.
//
// Claude Code, when it detects it is talking through a proxy classified as
// Chinese-org/reseller (known), AI-lab-keyword (labKw), or in a Chinese
// timezone (cnTZ), steganographically marks the "Today's date is <date>." line
// it injects into the prompt: it swaps the apostrophe for a visually-identical
// homoglyph (U+2019/U+02BC/U+02B9…) and, under cnTZ, swaps the date separator
// '-' for '/'. That encodes a 2-bit classification of the request's origin that
// downstream parties can recover from the exact code points.
//
// rewriteDateFingerprintInPlace normalizes that line back to the clean,
// official-direct form (ASCII apostrophe U+0027, '-' date separator) so
// outbound traffic through the proxy carries no such mark. It touches ONLY the
// date line and ONLY those two character classes — user prompt text (which may
// legitimately contain curly apostrophes) is left untouched.
//
// This must run on the parsed body BEFORE the final json.Marshal + cch
// recompute in Engine.Apply, so the cch attestation covers the cleaned bytes.

// dateFingerprintLineRe matches the injected line "Today<apostrophe>s date is
// <date>.". The apostrophe slot is `.` so any homoglyph variant matches; the
// date accepts '-' or '/' separators. Mirrors probe.DateLine in
// internal/probe/normalize.go (kept as a local copy to avoid a disguise→probe
// import; the two must stay in sync).
var dateFingerprintLineRe = regexp.MustCompile(`Today.s date is [0-9]{4}[-/][0-9]{2}[-/][0-9]{2}\.`)

// homoglyphApostrophes are the non-ASCII code points the fingerprint uses in
// the apostrophe slot; each is normalized to U+0027.
var homoglyphApostrophes = map[rune]bool{
	0x2019: true, // ’ right single quotation mark
	0x2018: true, // ‘ left single quotation mark
	0x02BC: true, // ʼ modifier letter apostrophe
	0x02B9: true, // ʹ modifier letter prime
	0x2032: true, // ′ prime
}

// rewriteDateFingerprintInPlace walks the system prompt and message content of
// a parsed request body and normalizes the covert date line in every string it
// finds. Returns true if any string was changed.
func rewriteDateFingerprintInPlace(parsed map[string]interface{}) bool {
	if parsed == nil {
		return false
	}
	changed := false
	apply := func(s string) string {
		out, did := normalizeDateLine(s)
		if did {
			changed = true
		}
		return out
	}
	walkPromptStrings(parsed, apply)
	return changed
}

// walkPromptStrings applies fn to every prompt-template string in parsed: the
// system field (string or list of {text} blocks) and each message's content
// (string or list of {type:"text", text} blocks). It mutates in place.
func walkPromptStrings(parsed map[string]interface{}, fn func(string) string) {
	// system: string | []block
	switch sys := parsed["system"].(type) {
	case string:
		parsed["system"] = fn(sys)
	case []interface{}:
		rewriteBlockList(sys, fn)
	}

	// messages: []{ content: string | []block }
	msgs, ok := parsed["messages"].([]interface{})
	if !ok {
		return
	}
	for _, m := range msgs {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			msg["content"] = fn(content)
		case []interface{}:
			rewriteBlockList(content, fn)
		}
	}
}

// rewriteBlockList applies fn to the "text" field of every text block in a
// content/system block list, mutating each block map in place.
func rewriteBlockList(blocks []interface{}, fn func(string) string) {
	for _, b := range blocks {
		block, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		// Only text blocks carry the carrier; a missing "type" is treated as
		// text (system blocks in some client versions omit it).
		if t, hasType := block["type"].(string); hasType && t != "text" {
			continue
		}
		text, ok := block["text"].(string)
		if !ok {
			continue
		}
		block["text"] = fn(text)
	}
}

// normalizeDateLine finds the covert date line inside s (if present) and
// rewrites only that matched span: homoglyph apostrophes → U+0027, date
// separator '/' → '-'. Everything else in s is left byte-for-byte identical.
// Returns the (possibly unchanged) string and whether it changed.
func normalizeDateLine(s string) (string, bool) {
	loc := dateFingerprintLineRe.FindStringIndex(s)
	if loc == nil {
		return s, false
	}
	segment := s[loc[0]:loc[1]]
	cleaned := normalizeSegment(segment)
	if cleaned == segment {
		return s, false
	}
	return s[:loc[0]] + cleaned + s[loc[1]:], true
}

// normalizeSegment rewrites the two carrier character classes within a single
// matched date-line segment.
func normalizeSegment(seg string) string {
	var b strings.Builder
	b.Grow(len(seg))
	for _, r := range seg {
		switch {
		case homoglyphApostrophes[r]:
			b.WriteByte('\'')
		case r == '/':
			b.WriteByte('-')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
