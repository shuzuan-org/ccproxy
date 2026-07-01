package probe

import (
	"fmt"
	"strings"
)

// Two-location comparison.
//
// The env-matrix probe (probe env) flips one environment dimension at a time on
// a single machine. compare is the other half: it takes two request bodies
// captured on two *real* machines — e.g. one US VPS and one CN VPS running the
// same client version against the same fixed prompt — and diffs them. This
// catches any fingerprint that varies with the whole real environment (egress
// IP, geo, timezone, locale) at once, without having to enumerate the signals
// in advance. It is pure offline analysis: capture happens elsewhere (ccproxy
// record mode, mitmproxy, etc.); compare only reads the two bodies.
//
// Both bodies are normalized (dynamic ids masked) before diffing so per-request
// nonces do not masquerade as geo-sensitive drift. Only structural noise is
// removed — character-level differences (the fingerprint carriers) are left for
// the diff to surface.

// CompareReport is the result of comparing two captured bodies.
type CompareReport struct {
	LabelA, LabelB  string
	DateLineA       string
	DateLineB       string
	Hunks           []DiffHunk // date-line diff, A→B
	FindingsA       []Finding  // confusables in A's date line
	FindingsB       []Finding  // confusables in B's date line
	NormalizedEqual bool       // whole normalized bodies identical
	NormalizeErrA   error
	NormalizeErrB   error
}

// Compare normalizes and diffs two captured request bodies. labelA/labelB name
// the two sides (e.g. "us", "cn"). It focuses the character-level diff on the
// covert date line (the known carrier) to avoid noise, but also reports whether
// the whole normalized bodies are byte-identical — a difference there beyond
// the date line is a signal worth a closer look.
func Compare(labelA, labelB string, bodyA, bodyB []byte) CompareReport {
	r := CompareReport{LabelA: labelA, LabelB: labelB}

	normA, errA := Normalize(bodyA)
	normB, errB := Normalize(bodyB)
	r.NormalizeErrA, r.NormalizeErrB = errA, errB
	if errA == nil && errB == nil {
		r.NormalizedEqual = normA == normB
	}

	r.DateLineA = DateLine(bodyA)
	r.DateLineB = DateLine(bodyB)
	r.FindingsA = ScanConfusables(r.DateLineA)
	r.FindingsB = ScanConfusables(r.DateLineB)
	r.Hunks = Diff(r.DateLineA, r.DateLineB)
	return r
}

// Render produces the textual comparison report.
func (r CompareReport) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "═══ ccproxy probe compare — %s vs %s ═══\n\n", r.LabelA, r.LabelB)

	if r.NormalizeErrA != nil {
		fmt.Fprintf(&b, "⚠ %s body failed to parse: %v\n", r.LabelA, r.NormalizeErrA)
	}
	if r.NormalizeErrB != nil {
		fmt.Fprintf(&b, "⚠ %s body failed to parse: %v\n", r.LabelB, r.NormalizeErrB)
	}

	fmt.Fprintf(&b, "%s date line: %s\n", r.LabelA, dateLineOrNone(r.DateLineA))
	fmt.Fprintf(&b, "%s date line: %s\n\n", r.LabelB, dateLineOrNone(r.DateLineB))

	renderFindings(&b, r.LabelA, r.FindingsA)
	renderFindings(&b, r.LabelB, r.FindingsB)

	// Date-line diff.
	if r.DateLineA == "" && r.DateLineB == "" {
		b.WriteString("· no date-injection line found on either side\n")
	} else if len(r.Hunks) == 0 {
		b.WriteString("= date lines identical\n")
	} else {
		fmt.Fprintf(&b, "Δ %d char(s) differ (%s → %s):\n", len(r.Hunks), r.LabelA, r.LabelB)
		for _, h := range r.Hunks {
			fmt.Fprintf(&b, "    @rune %d: %s(%s) → %s(%s)  «%s»\n",
				h.RuneIndex,
				visualRune(h.Base), h.BaseCP,
				visualRune(h.Variant), h.VariantCP,
				h.Context)
		}
	}

	// Whole-body note.
	b.WriteString("\n─── 汇总 ───\n")
	if len(r.Hunks) > 0 {
		fmt.Fprintf(&b, "  date line: %s\n", summarizeHunks(r.Hunks))
	}
	if !r.NormalizedEqual && r.NormalizeErrA == nil && r.NormalizeErrB == nil {
		b.WriteString("  ⚠ 归一化后整体 body 仍不同 — 差异不止 date 行,建议细查其它字段\n")
	} else if len(r.Hunks) == 0 && r.NormalizedEqual {
		b.WriteString("  ✓ 两侧归一化后逐字节一致 — 未见地理敏感指纹\n")
	}
	return b.String()
}

func dateLineOrNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return visualize(s)
}

func renderFindings(b *strings.Builder, label string, findings []Finding) {
	for _, f := range findings {
		like := "invisible"
		if f.LooksLike != 0 {
			like = fmt.Sprintf("looks like %q", string(f.LooksLike))
		}
		fmt.Fprintf(b, "⚑ %s: %s %s (%s) @rune %d\n", label, f.CodePoint, f.Category, like, f.RuneIndex)
	}
}
