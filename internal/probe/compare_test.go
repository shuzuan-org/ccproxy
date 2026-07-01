package probe

import (
	"strings"
	"testing"
)

func TestCompare_DetectsGeoFingerprint(t *testing.T) {
	// us: clean; cn: homoglyph apostrophe + slash date.
	us := []byte(`{"system":"Today's date is 2026-07-01.","metadata":{"user_id":"sess-a"}}`)
	cn := []byte(`{"system":"Today’s date is 2026/07/01.","metadata":{"user_id":"sess-b"}}`)
	rep := Compare("us", "cn", us, cn)

	if len(rep.Hunks) == 0 {
		t.Fatal("expected date-line differences between us and cn")
	}
	out := rep.Render()
	if !strings.Contains(out, "U+2019") {
		t.Errorf("cn homoglyph apostrophe should be reported:\n%s", out)
	}
	if !strings.Contains(out, "日期分隔符") {
		t.Errorf("date separator drift should be summarized:\n%s", out)
	}
	// cn side confusable scan should flag the homoglyph.
	if len(rep.FindingsB) == 0 {
		t.Error("cn findings should include the homoglyph apostrophe")
	}
	if len(rep.FindingsA) != 0 {
		t.Error("us (clean) side should have no confusable findings")
	}
}

func TestCompare_IdenticalAfterMaskingIDs(t *testing.T) {
	// Same semantic content, only session ids differ => normalized equal, no
	// date-line drift. IDs must not masquerade as geo drift.
	a := []byte(`{"system":"Today's date is 2026-07-01.","metadata":{"user_id":"11111111-1111-4111-8111-111111111111"}}`)
	b := []byte(`{"system":"Today's date is 2026-07-01.","metadata":{"user_id":"22222222-2222-4222-8222-222222222222"}}`)
	rep := Compare("us", "cn", a, b)

	if len(rep.Hunks) != 0 {
		t.Errorf("date lines should be identical, got hunks: %+v", rep.Hunks)
	}
	if !rep.NormalizedEqual {
		t.Errorf("bodies differing only in ids must normalize equal")
	}
	if !strings.Contains(rep.Render(), "未见地理敏感指纹") {
		t.Errorf("clean comparison should report no fingerprint:\n%s", rep.Render())
	}
}

func TestCompare_WholeBodyDiffersBeyondDateLine(t *testing.T) {
	// Same date line, but a different (non-id) field — flag "beyond date line".
	a := []byte(`{"system":"Today's date is 2026-07-01.","model":"sonnet"}`)
	b := []byte(`{"system":"Today's date is 2026-07-01.","model":"opus"}`)
	rep := Compare("us", "cn", a, b)
	if rep.NormalizedEqual {
		t.Fatal("bodies differ in model, should not be normalized-equal")
	}
	if !strings.Contains(rep.Render(), "差异不止 date 行") {
		t.Errorf("should warn about differences beyond the date line:\n%s", rep.Render())
	}
}

func TestCompare_NoDateLineEitherSide(t *testing.T) {
	a := []byte(`{"system":"no date here"}`)
	b := []byte(`{"system":"also nothing"}`)
	rep := Compare("us", "cn", a, b)
	if !strings.Contains(rep.Render(), "no date-injection line found on either side") {
		t.Errorf("absent date line on both sides should be reported:\n%s", rep.Render())
	}
}

func TestCompare_MalformedBodyReported(t *testing.T) {
	rep := Compare("us", "cn", []byte(`{bad json`), []byte(`{"system":"Today's date is 2026-07-01."}`))
	if rep.NormalizeErrA == nil {
		t.Fatal("expected parse error for malformed us body")
	}
	if !strings.Contains(rep.Render(), "failed to parse") {
		t.Errorf("malformed body should be reported:\n%s", rep.Render())
	}
}
