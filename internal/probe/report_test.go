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
