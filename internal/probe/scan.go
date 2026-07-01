// Package probe implements a differential fingerprint-discovery harness.
//
// The threat model: a client binary (e.g. Claude Code) may embed covert,
// per-request steganographic fingerprints that vary with the *hidden*
// environment (proxy hostname, timezone, locale) — encoding a classification
// into visually-identical but code-point-distinct characters in the outbound
// request body. The implementation is deliberately obfuscated and scattered,
// but the *goal* is convergent: it must make outbound bytes differ by
// environment. So instead of fighting the obfuscated code, we set a trap at
// the point it cannot avoid — the outbound HTTP body — and discover
// fingerprints by differential testing: hold the semantic input fixed, flip
// one environment dimension, and observe whether the bytes drift.
//
// scan.go is the backstop layer: it flags "looks-like-ASCII but isn't"
// characters (homoglyphs, zero-width marks, bidi controls) that are the
// classic carriers for this kind of steganography.
package probe

import (
	"fmt"
	"unicode"
)

// Finding is a single suspicious code point discovered in a string.
type Finding struct {
	// RuneIndex is the position of the character measured in runes (not bytes),
	// counting from 0.
	RuneIndex int
	// Rune is the offending code point.
	Rune rune
	// CodePoint is the "U+XXXX" textual form of Rune.
	CodePoint string
	// LooksLike is the ASCII character this rune is visually confusable with,
	// or 0 if it is an invisible/formatting character with no ASCII lookalike.
	LooksLike rune
	// Category is a short human label: "apostrophe", "hyphen", "zero-width",
	// "bidi", "variation-selector", "other-nonascii".
	Category string
	// Context is a short surrounding snippet (with the offending rune included)
	// to help locate the finding in the original text.
	Context string
}

// confusable maps a suspicious code point to the ASCII character it imitates
// and a category label. A LooksLike of 0 means "invisible / no ASCII
// lookalike" (zero-width, bidi, variation selectors).
type confusable struct {
	looksLike rune
	category  string
}

// confusables is a deliberately small, curated table. It is NOT meant to be an
// exhaustive Unicode confusables database — it covers the character families
// that are realistic steganographic carriers inside an otherwise-ASCII prompt
// template:
//
//   - apostrophe family (the exact carrier used by the observed 2.1.197
//     fingerprint: U+2019, U+02BC, U+02B9, plus common siblings)
//   - hyphen/dash family (a "-" swapped for a look-alike is another 1-bit slot)
//   - quotation marks
//   - zero-width / invisible characters (pure steganography, no visual trace)
//   - bidirectional controls and variation selectors
//
// Anything non-ASCII that is not in this table is still reported as
// "other-nonascii" by ScanConfusables when scanning template regions, so a
// novel carrier we did not anticipate is not silently missed.
var confusables = map[rune]confusable{
	// Apostrophe family — imitates U+0027 '
	0x2019: {'\'', "apostrophe"}, // ’ right single quotation mark
	0x2018: {'\'', "apostrophe"}, // ‘ left single quotation mark
	0x02BC: {'\'', "apostrophe"}, // ʼ modifier letter apostrophe
	0x02B9: {'\'', "apostrophe"}, // ʹ modifier letter prime
	0x2032: {'\'', "apostrophe"}, // ′ prime
	0x0060: {'\'', "apostrophe"}, // ` grave accent (ASCII but confusable)
	0x00B4: {'\'', "apostrophe"}, // ´ acute accent

	// Quotation mark family — imitates U+0022 "
	0x201C: {'"', "quote"}, // “ left double quotation mark
	0x201D: {'"', "quote"}, // ” right double quotation mark
	0x2033: {'"', "quote"}, // ″ double prime

	// Hyphen/dash family — imitates U+002D -
	0x2010: {'-', "hyphen"}, // ‐ hyphen
	0x2011: {'-', "hyphen"}, // ‑ non-breaking hyphen
	0x2012: {'-', "hyphen"}, // ‒ figure dash
	0x2013: {'-', "hyphen"}, // – en dash
	0x2014: {'-', "hyphen"}, // — em dash
	0x2015: {'-', "hyphen"}, // ― horizontal bar
	0x2212: {'-', "hyphen"}, // − minus sign

	// Zero-width / invisible — no ASCII lookalike (looksLike = 0)
	0x200B: {0, "zero-width"}, // zero width space
	0x200C: {0, "zero-width"}, // zero width non-joiner
	0x200D: {0, "zero-width"}, // zero width joiner
	0xFEFF: {0, "zero-width"}, // zero width no-break space / BOM
	0x2060: {0, "zero-width"}, // word joiner
	0x00AD: {0, "zero-width"}, // soft hyphen (invisible unless line-broken)

	// Bidirectional controls — no ASCII lookalike
	0x200E: {0, "bidi"}, // left-to-right mark
	0x200F: {0, "bidi"}, // right-to-left mark
	0x202A: {0, "bidi"}, // left-to-right embedding
	0x202B: {0, "bidi"}, // right-to-left embedding
	0x202C: {0, "bidi"}, // pop directional formatting
	0x202D: {0, "bidi"}, // left-to-right override
	0x202E: {0, "bidi"}, // right-to-left override
}

// ScanConfusables walks s rune-by-rune and reports every non-ASCII code point.
// Characters present in the curated confusables table are reported with their
// specific category and ASCII lookalike; any other non-ASCII rune is reported
// as "other-nonascii" so an unanticipated carrier is never silently dropped.
//
// Pure ASCII input yields no findings. This is intended for scanning fixed
// template regions (e.g. the system-prompt text a client emits), where any
// non-ASCII character is inherently suspicious; do not run it over
// user-supplied free text, which legitimately contains non-ASCII.
func ScanConfusables(s string) []Finding {
	var findings []Finding
	runes := []rune(s)
	for i, r := range runes {
		if r < 0x80 {
			// Plain ASCII, except we still flag the two ASCII characters that
			// are apostrophe-confusable and listed in the table (` and, if
			// added, others). They are < 0x80 so handle explicitly.
			if c, ok := confusables[r]; ok {
				findings = append(findings, mkFinding(runes, i, r, c))
			}
			continue
		}
		if c, ok := confusables[r]; ok {
			findings = append(findings, mkFinding(runes, i, r, c))
			continue
		}
		// Non-ASCII, not in table: still report so novel carriers surface.
		findings = append(findings, mkFinding(runes, i, r, confusable{0, "other-nonascii"}))
	}
	return findings
}

func mkFinding(runes []rune, i int, r rune, c confusable) Finding {
	return Finding{
		RuneIndex: i,
		Rune:      r,
		CodePoint: codePoint(r),
		LooksLike: c.looksLike,
		Category:  c.category,
		Context:   contextSnippet(runes, i, 12),
	}
}

// codePoint renders r as "U+XXXX" (at least 4 hex digits, upper case).
func codePoint(r rune) string {
	return fmt.Sprintf("U+%04X", r)
}

// contextSnippet returns up to `radius` runes on each side of position i,
// with the run itself included. Non-printable characters in the context are
// replaced with a visible placeholder so the snippet stays readable.
func contextSnippet(runes []rune, i, radius int) string {
	lo := i - radius
	if lo < 0 {
		lo = 0
	}
	hi := i + radius + 1
	if hi > len(runes) {
		hi = len(runes)
	}
	out := make([]rune, 0, hi-lo)
	for j := lo; j < hi; j++ {
		r := runes[j]
		if r == '\n' {
			out = append(out, '↵') // ↵ to keep snippet on one line
			continue
		}
		if !unicode.IsPrint(r) {
			out = append(out, '�') // � for invisible/control
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
