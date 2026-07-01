package probe

import (
	"fmt"
	"sort"
	"strings"
)

// VariantResult is the outcome of driving the client under one variant.
type VariantResult struct {
	Variant Variant
	// Driven is true when the client actually ran and emitted a captured body.
	Driven bool
	// SkipReason explains why Driven is false (e.g. host resolve unavailable,
	// client error). Never left empty when Driven is false.
	SkipReason string
	// RawBody is the captured outbound request body (nil when not driven).
	RawBody []byte
	// DateLine is the covert date-injection line located anywhere in the body
	// (the primary known carrier). Empty if not found.
	DateLine string
	// SystemText is the text region diffed and scanned. For the first stage it
	// is set to DateLine (the precise carrier) to avoid false positives from
	// legitimate markdown elsewhere in the prompt.
	SystemText string
	// Findings are confusable/invisible characters found in SystemText.
	Findings []Finding
}

// Report aggregates all variant results and renders a human-readable summary.
type Report struct {
	Results []VariantResult
	byLabel map[string]*VariantResult
}

// BuildReport assembles a report from variant results. Each variant is diffed
// against its reference (Variant.Ref, defaulting to "baseline").
func BuildReport(results []VariantResult) *Report {
	r := &Report{Results: results, byLabel: make(map[string]*VariantResult, len(results))}
	for i := range results {
		r.byLabel[results[i].Variant.Label] = &results[i]
	}
	return r
}

// refFor returns the driven reference result for a variant, or nil if its
// reference was not driven (so no diff can be produced).
func (r *Report) refFor(v Variant) *VariantResult {
	label := v.Ref
	if label == "" {
		label = "baseline"
	}
	if ref, ok := r.byLabel[label]; ok && ref.Driven {
		return ref
	}
	return nil
}

// Render produces the textual report.
func (r *Report) Render() string {
	var b strings.Builder
	b.WriteString("═══ ccproxy probe env — 隐蔽指纹差分报告 ═══\n\n")

	// Per-variant section.
	for i := range r.Results {
		res := &r.Results[i]
		fmt.Fprintf(&b, "▸ %-14s %s\n", res.Variant.Label, res.Variant.Desc)
		if !res.Driven {
			fmt.Fprintf(&b, "    ⚠ 未驱动: %s\n\n", res.SkipReason)
			continue
		}
		// Show the captured date line if we can find it (the known carrier).
		if line := extractDateLine(res.SystemText); line != "" {
			fmt.Fprintf(&b, "    date line: %s\n", visualize(line))
		}
		// Confusable scan on the system text.
		if len(res.Findings) > 0 {
			for _, f := range res.Findings {
				like := "invisible"
				if f.LooksLike != 0 {
					like = fmt.Sprintf("looks like %q", string(f.LooksLike))
				}
				fmt.Fprintf(&b, "    ⚑ %s %s (%s) @rune %d  «%s»\n",
					f.CodePoint, f.Category, like, f.RuneIndex, f.Context)
			}
		}
		// Report an absent carrier explicitly — a driven variant with no date
		// line is a distinct outcome from "not driven" and from "identical".
		if res.DateLine == "" {
			b.WriteString("    · no date-injection line found in captured body\n\n")
			continue
		}
		// Diff against this variant's reference (Ref, default baseline).
		ref := r.refFor(res.Variant)
		if ref == nil {
			if refLabel(res.Variant) != res.Variant.Label {
				fmt.Fprintf(&b, "    · reference %q not driven — no diff\n", refLabel(res.Variant))
			}
			b.WriteString("\n")
			continue
		}
		if res.Variant.Label == ref.Variant.Label {
			b.WriteString("\n") // this IS a reference variant
			continue
		}
		hunks := Diff(ref.SystemText, res.SystemText)
		if len(hunks) == 0 {
			fmt.Fprintf(&b, "    = identical to %s\n", ref.Variant.Label)
		} else {
			fmt.Fprintf(&b, "    Δ %d char(s) differ from %s:\n", len(hunks), ref.Variant.Label)
			for _, h := range hunks {
				fmt.Fprintf(&b, "        @rune %d: %s(%s) → %s(%s)  «%s»\n",
					h.RuneIndex,
					visualRune(h.Base), h.BaseCP,
					visualRune(h.Variant), h.VariantCP,
					h.Context)
			}
		}
		b.WriteString("\n")
	}

	// Summary table: which dimension triggered which fingerprint bits.
	b.WriteString("─── 环境敏感指纹位汇总 ───\n")
	any := false
	for i := range r.Results {
		res := &r.Results[i]
		if !res.Driven || res.DateLine == "" {
			continue
		}
		ref := r.refFor(res.Variant)
		if ref == nil || ref.Variant.Label == res.Variant.Label {
			continue
		}
		hunks := Diff(ref.SystemText, res.SystemText)
		if len(hunks) == 0 {
			continue
		}
		any = true
		fmt.Fprintf(&b, "  %-14s → %s\n", res.Variant.Label, summarizeHunks(hunks))
	}
	if !any {
		b.WriteString("  ✓ 无环境敏感差异 — 该客户端在本轮维度下未表现出指纹漂移\n")
	}
	return b.String()
}

// refLabel returns the reference label for a variant (its Ref, or "baseline").
func refLabel(v Variant) string {
	if v.Ref == "" {
		return "baseline"
	}
	return v.Ref
}

// summarizeHunks turns a hunk list into a one-line human summary, e.g.
// "apostrophe ' → ’ (U+2019); date sep - → /".
func summarizeHunks(hunks []DiffHunk) string {
	var parts []string
	apos := ""
	dateSep := 0
	for _, h := range hunks {
		switch {
		case h.Base == '\'' && h.Variant != '\'':
			apos = fmt.Sprintf("撇号 ' → %s (%s)", visualRune(h.Variant), h.VariantCP)
		case h.Base == '-' && h.Variant == '/':
			dateSep++
		default:
			parts = append(parts, fmt.Sprintf("%s→%s@%d", h.BaseCP, h.VariantCP, h.RuneIndex))
		}
	}
	if apos != "" {
		parts = append([]string{apos}, parts...)
	}
	if dateSep > 0 {
		parts = append(parts, fmt.Sprintf("日期分隔符 - → / ×%d", dateSep))
	}
	sort.SliceStable(parts, func(i, j int) bool { return parts[i] < parts[j] })
	return strings.Join(parts, "; ")
}

// extractDateLine returns the first line containing "date is" (the observed
// carrier line), or "".
func extractDateLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, "date is") {
			return strings.TrimSpace(ln)
		}
	}
	return ""
}

// visualize renders a string with each non-ASCII rune annotated inline as
// «char U+XXXX» so the reader sees exactly which code point is present.
func visualize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
		} else {
			fmt.Fprintf(&b, "«%c U+%04X»", r, r)
		}
	}
	return b.String()
}

// visualRune renders a single rune printably.
func visualRune(r rune) string {
	if r == 0 {
		return "∅"
	}
	if r < 0x20 || r == 0x7f {
		return "�"
	}
	return string(r)
}
