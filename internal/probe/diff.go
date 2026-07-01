package probe

import "fmt"

// DiffHunk is one position where two strings differ, described at the code
// point level. Because covert fingerprints hide in "visually identical but
// code-point-distinct" swaps (' vs ’, - vs /), a byte- or rune-level diff is
// exactly the right granularity: it surfaces changes a line diff would render
// as identical.
type DiffHunk struct {
	// RuneIndex is the aligned position (in runes) where the difference occurs.
	RuneIndex int
	// Base and Variant are the differing runes. Either may be 0 when one side
	// is shorter than the other (insertion/deletion at the tail).
	Base    rune
	Variant rune
	// BaseCP and VariantCP are the "U+XXXX" forms of Base and Variant.
	BaseCP    string
	VariantCP string
	// Context is a short snippet from the variant side around the difference.
	Context string
}

// Diff compares base and variant rune-by-rune and returns every position that
// differs. It performs a simple positional alignment (index i vs index i),
// which is the correct model here: fingerprint carriers are in-place
// substitutions of equal-length semantic content, not insertions. A trailing
// length mismatch is reported as hunks with a zero rune on the short side.
//
// Both inputs should already be normalized (see Normalize) so that structural
// noise — JSON key ordering, whitespace, masked dynamic fields — does not
// masquerade as a difference.
func Diff(base, variant string) []DiffHunk {
	br := []rune(base)
	vr := []rune(variant)
	n := len(br)
	if len(vr) > n {
		n = len(vr)
	}
	var hunks []DiffHunk
	for i := 0; i < n; i++ {
		var b, v rune
		if i < len(br) {
			b = br[i]
		}
		if i < len(vr) {
			v = vr[i]
		}
		if b == v {
			continue
		}
		hunks = append(hunks, DiffHunk{
			RuneIndex: i,
			Base:      b,
			Variant:   v,
			BaseCP:    cpOrNone(b),
			VariantCP: cpOrNone(v),
			Context:   contextSnippet(vr, i, 16),
		})
	}
	return hunks
}

// cpOrNone renders a code point, or "∅" for the zero rune used to mark a
// length mismatch (one side ran out of runes).
func cpOrNone(r rune) string {
	if r == 0 {
		return "∅"
	}
	return fmt.Sprintf("U+%04X", r)
}
