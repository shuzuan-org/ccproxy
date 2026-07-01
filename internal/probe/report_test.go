package probe

import (
	"strings"
	"testing"
)

func mkResult(label, sysText string, driven bool, skip string) VariantResult {
	r := VariantResult{
		Variant: Variant{Label: label, Desc: label + " desc"},
		Driven:  driven,
	}
	if driven {
		r.DateLine = sysText
		r.SystemText = sysText
		r.Findings = ScanConfusables(sysText)
	} else {
		r.SkipReason = skip
	}
	return r
}

func TestReport_DetectsApostropheAndDateDrift(t *testing.T) {
	results := []VariantResult{
		mkResult("baseline", "Today's date is 2026-07-01.", true, ""),
		mkResult("host_cn", "Today’s date is 2026-07-01.", true, ""),       // apostrophe drift
		mkResult("tz_cn", "Today's date is 2026/07/01.", true, ""),         // date sep drift
		mkResult("host_cn_tz_cn", "Today’s date is 2026/07/01.", true, ""), // both
	}
	out := BuildReport(results).Render()

	if !strings.Contains(out, "host_cn") || !strings.Contains(out, "U+2019") {
		t.Errorf("report should flag host_cn apostrophe U+2019:\n%s", out)
	}
	if !strings.Contains(out, "日期分隔符") {
		t.Errorf("report should flag date separator drift for tz_cn:\n%s", out)
	}
	// Summary section present.
	if !strings.Contains(out, "环境敏感指纹位汇总") {
		t.Errorf("report missing summary section:\n%s", out)
	}
}

func TestReport_CleanClientNoDrift(t *testing.T) {
	// A client that emits identical clean text under every variant => report
	// must explicitly say "no drift", not silently imply coverage.
	results := []VariantResult{
		mkResult("baseline", "Today's date is 2026-07-01.", true, ""),
		mkResult("tz_cn", "Today's date is 2026-07-01.", true, ""),
	}
	out := BuildReport(results).Render()
	if !strings.Contains(out, "无环境敏感差异") {
		t.Errorf("clean client should report no drift:\n%s", out)
	}
}

func TestReport_SkippedVariantHonestlyMarked(t *testing.T) {
	results := []VariantResult{
		mkResult("baseline", "Today's date is 2026-07-01.", true, ""),
		mkResult("host_cn", "", false, "host resolve unavailable"),
	}
	out := BuildReport(results).Render()
	if !strings.Contains(out, "未驱动") || !strings.Contains(out, "host resolve unavailable") {
		t.Errorf("skipped variant must be honestly marked as not driven:\n%s", out)
	}
}

func TestReport_DiffsAgainstRefNotBaseline(t *testing.T) {
	// host_cn must diff against host_baseline (clean domain), NOT baseline.
	// Here baseline and host_baseline carry different date lines to prove the
	// reference selection matters: if the report wrongly used baseline, the
	// apostrophe drift would be masked/miscounted.
	hostBase := mkResult("host_baseline", "Today's date is 2026-07-01.", true, "")
	hostCN := mkResult("host_cn", "Today’s date is 2026-07-01.", true, "")
	hostCN.Variant.Ref = "host_baseline"
	// A baseline with a DELIBERATELY different line — must be ignored for host_cn.
	base := mkResult("baseline", "Today's date is 1999-01-01.", true, "")

	out := BuildReport([]VariantResult{base, hostBase, hostCN}).Render()

	if !strings.Contains(out, "differ from host_baseline") {
		t.Errorf("host_cn must be diffed against host_baseline:\n%s", out)
	}
	if !strings.Contains(out, "U+2019") {
		t.Errorf("apostrophe drift vs host_baseline should be reported:\n%s", out)
	}
	// The summary line for host_cn should mention the apostrophe, once.
	if strings.Count(out, "host_cn") < 1 {
		t.Errorf("host_cn missing from report:\n%s", out)
	}
}

func TestReport_DrivenButNoDateLine(t *testing.T) {
	// Distinct outcome from "not driven": the client ran but emitted no carrier.
	res := VariantResult{Variant: Variant{Label: "tz_cn"}, Driven: true, DateLine: ""}
	base := mkResult("baseline", "Today's date is 2026-07-01.", true, "")
	out := BuildReport([]VariantResult{base, res}).Render()
	if !strings.Contains(out, "no date-injection line") {
		t.Errorf("driven-but-no-carrier must be reported distinctly:\n%s", out)
	}
}
