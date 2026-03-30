package disguise

import "net/http"

// DefaultHeaders are the HTTP headers that mimic Claude CLI.
// Used as fallback when no per-account fingerprint is available.
// Keep these in sync with sub2api/internal/pkg/claude/constants.go.
var DefaultHeaders = map[string]string{
	"User-Agent":                    "claude-cli/2.1.22 (external, cli)",
	"X-Stainless-Package-Version":  "0.70.0",
	"X-Stainless-OS":               "Linux",
	"X-Stainless-Arch":             "arm64",
	"X-Stainless-Runtime-Version":  "v24.13.0",
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
