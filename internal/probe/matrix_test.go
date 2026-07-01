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

func TestSelect_PullsInHostReference(t *testing.T) {
	// Selecting host_cn must also pull in host_baseline (its Ref), else the
	// host diff has no clean-domain reference and would fall back to the dirty
	// IP-literal baseline — the contamination this fix exists to prevent.
	m := DefaultMatrix()
	got := Select(m, map[string]bool{"host_cn": true})
	labels := map[string]bool{}
	for _, v := range got {
		labels[v.Label] = true
	}
	if !labels["host_baseline"] {
		t.Errorf("selecting host_cn must pull in host_baseline; got %v", labels)
	}
	if !labels["host_cn"] {
		t.Errorf("host_cn missing from selection")
	}
}

func TestHostVariants_ReferenceCleanDomain(t *testing.T) {
	m := DefaultMatrix()
	for _, v := range m {
		if v.Label == "host_cn" || v.Label == "host_reseller" || v.Label == "host_labkw" || v.Label == "host_cn_tz_cn" {
			if v.Ref != "host_baseline" {
				t.Errorf("%s.Ref = %q, want host_baseline (clean domain, not IP baseline)", v.Label, v.Ref)
			}
		}
	}
	// host_baseline itself must be a real domain, and not carry any signal.
	var hb Variant
	for _, v := range m {
		if v.Label == "host_baseline" {
			hb = v
		}
	}
	if hb.Hostname != cleanHost {
		t.Errorf("host_baseline hostname = %q, want %q", hb.Hostname, cleanHost)
	}
	if got := ScanConfusables(hb.Hostname); len(got) != 0 {
		t.Errorf("clean host must be plain ASCII")
	}
}
