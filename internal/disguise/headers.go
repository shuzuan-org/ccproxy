package disguise

import "net/http"

// DefaultHeaders are the HTTP headers that mimic Claude CLI.
// Used as fallback when no per-account fingerprint is available — in
// production the per-account fingerprint store learns the real client's
// tuple from the first CC request, so DefaultHeaders only matters for
// cold-start (an account that has never seen a real CC client).
//
// Version aligned with Claude CLI 2.1.126 observed traffic (mitmdump
// capture 2026-05-06 + binary inspection at
// /Users/binn/.local/share/claude/versions/2.1.126).
//
// IMPORTANT: the four fields below are a tightly-coupled tuple — each
// published Claude CLI release bundles one specific combination of (UA,
// Stainless SDK version, Node runtime version). Never bump one without
// verifying the others against a known-good reference. A mismatched tuple
// is a deterministic fingerprint signal (e.g. UA=2.1.126 + SDK 0.74.0
// does not exist in any real CLI release):
//
//   - User-Agent                  (CLI version)
//   - X-Stainless-Package-Version (SDK version bundled with that CLI)
//   - X-Stainless-Runtime-Version (Node version bundled with that CLI)
//   - anthropic-beta set          (see baseBetasNonHaiku / baseBetasHaiku in beta.go)
//
// The 2.1.126 tuple is: UA 2.1.126 + SDK 0.81.0 + Node v24.3.0.
//
// Why we keep it aligned with our cch ATTEST_KEYS era: cch.go's keys are
// extracted from the 2.1.114-2.1.126 binary range. If DefaultHeaders'
// User-Agent advertised a different era (e.g. 2.1.88), the body's
// cc_version field would carry "2.1.88" while we computed cch with 126-era
// keys — if Anthropic ever cross-checks the cc_version against a
// keys-era table, this would fail. Keeping them aligned eliminates one
// silent fingerprint vector during cold-start traffic.
var DefaultHeaders = map[string]string{
	"User-Agent":                  "claude-cli/2.1.126 (external, cli)",
	"X-Stainless-Package-Version": "0.81.0",
	"X-Stainless-OS":              "MacOS",
	"X-Stainless-Arch":            "arm64",
	"X-Stainless-Runtime-Version": "v24.3.0",
}

// ApplyHeaders sets all Claude CLI impersonation headers on the request.
// When fp is non-nil, per-account fingerprint values are used; otherwise
// DefaultHeaders provides the fallback.
func ApplyHeaders(req *http.Request, isStream bool, fp *Fingerprint) {
	if fp != nil {
		req.Header.Set("User-Agent", fp.UserAgent)
		req.Header.Set("X-Stainless-Package-Version", fp.StainlessPackageVersion)
		req.Header.Set("X-Stainless-OS", fp.StainlessOS)
		req.Header.Set("X-Stainless-Arch", fp.StainlessArch)
		req.Header.Set("X-Stainless-Runtime-Version", fp.StainlessRuntimeVersion)
	} else {
		for k, v := range DefaultHeaders {
			req.Header.Set(k, v)
		}
	}
	// Fixed headers (same for all accounts).
	// X-Stainless-* are Title-Case per the Stainless SDK wire format.
	req.Header.Set("X-Stainless-Lang", "js")
	req.Header.Set("X-Stainless-Runtime", "node")
	req.Header.Set("X-Stainless-Retry-Count", "0")
	req.Header.Set("X-Stainless-Timeout", "600")
	req.Header.Set("Accept", "application/json")
	// Anthropic SDK and x-app headers are lowercase on the wire (aligned with
	// real Claude CLI traffic capture; see sub2api header_util.go wire casing).
	delete(req.Header, "X-App")
	req.Header["x-app"] = []string{"cli"}
	delete(req.Header, "Anthropic-Dangerous-Direct-Browser-Access")
	req.Header["anthropic-dangerous-direct-browser-access"] = []string{"true"}
	delete(req.Header, "Anthropic-Version")
	req.Header["anthropic-version"] = []string{"2023-06-01"}
	if isStream {
		delete(req.Header, "X-Stainless-Helper-Method")
		req.Header["x-stainless-helper-method"] = []string{"stream"}
	}
}
