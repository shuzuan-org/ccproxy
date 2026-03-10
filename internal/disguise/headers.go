package disguise

import "net/http"

// DefaultHeaders are the HTTP headers that mimic Claude CLI 2.1.71
var DefaultHeaders = map[string]string{
	"User-Agent":                                "claude-cli/2.1.71 (external, cli)",
	"X-Stainless-Lang":                          "js",
	"X-Stainless-Package-Version":               "0.74.0",
	"X-Stainless-OS":                            "Linux",
	"X-Stainless-Arch":                          "arm64",
	"X-Stainless-Runtime":                       "node",
	"X-Stainless-Runtime-Version":               "v24.3.0",
	"X-Stainless-Retry-Count":                   "0",
	"X-Stainless-Timeout":                       "600",
	"X-App":                                     "cli",
	"Anthropic-Dangerous-Direct-Browser-Access": "true",
}

// ApplyHeaders sets all Claude CLI impersonation headers on the request.
func ApplyHeaders(req *http.Request, isStream bool) {
	for k, v := range DefaultHeaders {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	if isStream {
		req.Header.Set("X-Stainless-Helper-Method", "stream")
	}
}
