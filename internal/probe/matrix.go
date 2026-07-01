package probe

import "fmt"

// Variant is one environment configuration to drive the client under. Exactly
// one dimension is meant to differ from the baseline so that any resulting
// byte drift can be attributed to that dimension.
type Variant struct {
	// Label is the short id used in reports and on-disk filenames.
	Label string
	// Desc is a one-line human description of what this variant flips.
	Desc string
	// Env is the environment overlay applied on top of the base environment
	// for this variant (baseline values that other variants pin explicitly).
	Env map[string]string
	// Hostname, when non-empty, is the hostname the client's
	// ANTHROPIC_BASE_URL must present so the covert classifier sees it. The
	// runner is responsible for making this name resolve to the local sink
	// (via a temporary hosts entry). Empty means "connect straight to the sink
	// on 127.0.0.1" — used by the timezone/locale dimensions that do not need
	// a special hostname.
	Hostname string
	// NeedsHostResolve is true when Hostname must be resolved to loopback for
	// this variant to actually exercise the classifier's domain signals. On
	// platforms/permissions where that is not possible, the runner skips the
	// variant and reports it as "not driven" rather than faking a result.
	NeedsHostResolve bool
}

// The reseller hostname used for the reseller dimension. Chosen from the
// decoded blacklist embedded in the client; any entry works, this one is
// representative.
const resellerHost = "yunwu.ai"

// DefaultMatrix returns the first-stage environment matrix. baseline is always
// first and is the reference every other variant is diffed against.
//
// Dimensions:
//   - timezone  (cnTZ signal)      — tz_cn, tz_urumqi
//   - locale                        — lang_zh
//   - proxy hostname (known/labKw)  — host_cn, host_reseller, host_labkw
//   - combinations                  — host_cn_tz_cn
//
// The timezone/locale variants need no hostname trick and always run. The
// host_* variants require loopback name resolution (NeedsHostResolve) and are
// skipped-with-explanation when that is unavailable.
func DefaultMatrix() []Variant {
	// Baseline: a clean, non-Chinese, non-lab environment. Every field a
	// variant might flip is pinned here so the only difference is the variant's
	// own dimension.
	baseEnv := func() map[string]string {
		return map[string]string{
			"TZ":     "UTC",
			"LANG":   "en_US.UTF-8",
			"LC_ALL": "en_US.UTF-8",
		}
	}
	with := func(base map[string]string, kv ...string) map[string]string {
		m := make(map[string]string, len(base)+len(kv)/2)
		for k, v := range base {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}

	return []Variant{
		{
			Label: "baseline",
			Desc:  "clean: TZ=UTC, en_US, plain .com host",
			Env:   baseEnv(),
			// baseline connects straight to the sink; its hostname is the
			// loopback address, which the classifier treats as unknown.
		},
		{
			Label: "tz_cn",
			Desc:  "timezone Asia/Shanghai (cnTZ signal)",
			Env:   with(baseEnv(), "TZ", "Asia/Shanghai"),
		},
		{
			Label: "tz_urumqi",
			Desc:  "timezone Asia/Urumqi (cnTZ signal)",
			Env:   with(baseEnv(), "TZ", "Asia/Urumqi"),
		},
		{
			Label: "lang_zh",
			Desc:  "locale zh_CN.UTF-8",
			Env:   with(baseEnv(), "LANG", "zh_CN.UTF-8", "LC_ALL", "zh_CN.UTF-8"),
		},
		{
			Label:            "host_cn",
			Desc:             "proxy hostname ends in .cn (known signal, .cn catch-all)",
			Env:              baseEnv(),
			Hostname:         "probe-fp.cn",
			NeedsHostResolve: true,
		},
		{
			Label:            "host_reseller",
			Desc:             fmt.Sprintf("proxy hostname = blacklisted reseller %s (known signal)", resellerHost),
			Env:              baseEnv(),
			Hostname:         resellerHost,
			NeedsHostResolve: true,
		},
		{
			Label:            "host_labkw",
			Desc:             "proxy hostname contains AI-lab keyword 'deepseek' (labKw signal)",
			Env:              baseEnv(),
			Hostname:         "api.deepseek-probe.com",
			NeedsHostResolve: true,
		},
		{
			Label:            "host_cn_tz_cn",
			Desc:             "combination: .cn host + Asia/Shanghai (known + cnTZ)",
			Env:              with(baseEnv(), "TZ", "Asia/Shanghai"),
			Hostname:         "probe-fp.cn",
			NeedsHostResolve: true,
		},
	}
}

// Select filters the matrix to the requested labels (comma/space handled by the
// caller). An empty labels set returns the full matrix. Baseline is always
// included because every diff needs it as the reference.
func Select(all []Variant, labels map[string]bool) []Variant {
	if len(labels) == 0 {
		return all
	}
	var out []Variant
	for _, v := range all {
		if v.Label == "baseline" || labels[v.Label] {
			out = append(out, v)
		}
	}
	return out
}
