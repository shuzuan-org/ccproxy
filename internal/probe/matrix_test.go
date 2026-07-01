package probe

import "testing"

func TestDefaultMatrix_BaselineFirstAndClean(t *testing.T) {
	m := DefaultMatrix()
	if len(m) == 0 || m[0].Label != "baseline" {
		t.Fatalf("baseline must be first, got %+v", m[0])
	}
	if m[0].Env["TZ"] != "UTC" {
		t.Errorf("baseline TZ = %q, want UTC", m[0].Env["TZ"])
	}
	if m[0].NeedsHostResolve {
		t.Errorf("baseline must not need host resolve")
	}
}

func TestDefaultMatrix_SingleDimensionPerVariant(t *testing.T) {
	m := DefaultMatrix()
	base := m[0].Env
	// tz_cn should differ from baseline only in TZ.
	var tzcn Variant
	for _, v := range m {
		if v.Label == "tz_cn" {
			tzcn = v
		}
	}
	if tzcn.Env["TZ"] != "Asia/Shanghai" {
		t.Errorf("tz_cn TZ = %q", tzcn.Env["TZ"])
	}
	if tzcn.Env["LANG"] != base["LANG"] {
		t.Errorf("tz_cn should not change LANG")
	}
	if tzcn.NeedsHostResolve {
		t.Errorf("tz_cn is a timezone-only variant, must not need host resolve")
	}
}

func TestDefaultMatrix_HostVariantsFlagged(t *testing.T) {
	m := DefaultMatrix()
	want := map[string]string{
		"host_cn":       "probe-fp.cn",
		"host_reseller": resellerHost,
		"host_labkw":    "api.deepseek-probe.com",
	}
	seen := map[string]bool{}
	for _, v := range m {
		if h, ok := want[v.Label]; ok {
			seen[v.Label] = true
			if v.Hostname != h {
				t.Errorf("%s hostname = %q, want %q", v.Label, v.Hostname, h)
			}
			if !v.NeedsHostResolve {
				t.Errorf("%s must set NeedsHostResolve", v.Label)
			}
		}
	}
	for label := range want {
		if !seen[label] {
			t.Errorf("missing host variant %s", label)
		}
	}
}

func TestSelect_EmptyReturnsAll(t *testing.T) {
	m := DefaultMatrix()
	if got := Select(m, nil); len(got) != len(m) {
		t.Fatalf("empty select = %d, want %d", len(got), len(m))
	}
}

func TestSelect_AlwaysIncludesBaseline(t *testing.T) {
	m := DefaultMatrix()
	got := Select(m, map[string]bool{"tz_cn": true})
	if len(got) != 2 {
		t.Fatalf("select tz_cn = %d variants, want 2 (baseline + tz_cn)", len(got))
	}
	if got[0].Label != "baseline" {
		t.Errorf("baseline must be included and first")
	}
}
