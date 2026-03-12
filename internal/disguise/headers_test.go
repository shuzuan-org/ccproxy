package disguise

import (
	"net/http"
	"testing"
)

func TestApplyHeaders_AllDefaultHeaders(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}
	ApplyHeaders(req, false, nil)

	// Verify fixed headers are set.
	if got := req.Header.Get("X-Stainless-Lang"); got != "js" {
		t.Errorf("X-Stainless-Lang: expected %q, got %q", "js", got)
	}
	if got := req.Header.Get("X-Stainless-Runtime"); got != "node" {
		t.Errorf("X-Stainless-Runtime: expected %q, got %q", "node", got)
	}
	if got := req.Header.Get("X-App"); got != "cli" {
		t.Errorf("X-App: expected %q, got %q", "cli", got)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept: expected application/json, got %q", got)
	}
	if got := req.Header.Get("Anthropic-Version"); got != "2023-06-01" {
		t.Errorf("Anthropic-Version: expected 2023-06-01, got %q", got)
	}

	// With nil fingerprint, should use default headers.
	for k, v := range DefaultHeaders {
		if got := req.Header.Get(k); got != v {
			t.Errorf("header %q: expected %q, got %q", k, v, got)
		}
	}
}

func TestApplyHeaders_WithFingerprint(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}

	fp := &Fingerprint{
		UserAgent:               "claude-cli/2.1.25 (external, cli)",
		StainlessPackageVersion: "0.71.2",
		StainlessOS:             "Darwin",
		StainlessArch:           "arm64",
		StainlessRuntimeVersion: "v24.14.0",
	}
	ApplyHeaders(req, false, fp)

	if got := req.Header.Get("User-Agent"); got != fp.UserAgent {
		t.Errorf("User-Agent: expected %q, got %q", fp.UserAgent, got)
	}
	if got := req.Header.Get("X-Stainless-Package-Version"); got != fp.StainlessPackageVersion {
		t.Errorf("X-Stainless-Package-Version: expected %q, got %q", fp.StainlessPackageVersion, got)
	}
	if got := req.Header.Get("X-Stainless-OS"); got != fp.StainlessOS {
		t.Errorf("X-Stainless-OS: expected %q, got %q", fp.StainlessOS, got)
	}
	if got := req.Header.Get("X-Stainless-Arch"); got != fp.StainlessArch {
		t.Errorf("X-Stainless-Arch: expected %q, got %q", fp.StainlessArch, got)
	}
	if got := req.Header.Get("X-Stainless-Runtime-Version"); got != fp.StainlessRuntimeVersion {
		t.Errorf("X-Stainless-Runtime-Version: expected %q, got %q", fp.StainlessRuntimeVersion, got)
	}

	// Fixed headers should still be set regardless of fingerprint.
	if got := req.Header.Get("X-Stainless-Lang"); got != "js" {
		t.Errorf("X-Stainless-Lang: expected %q, got %q", "js", got)
	}
}

func TestApplyHeaders_StreamAddsHelperMethod(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}
	ApplyHeaders(req, true, nil)

	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "stream" {
		t.Errorf("expected X-Stainless-Helper-Method=stream, got %q", got)
	}
}

func TestApplyHeaders_NoStreamNoHelperMethod(t *testing.T) {
	t.Parallel()
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}
	ApplyHeaders(req, false, nil)

	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "" {
		t.Errorf("expected X-Stainless-Helper-Method to be absent, got %q", got)
	}
}

func TestIsHaikuModel_Haiku(t *testing.T) {
	t.Parallel()
	if !IsHaikuModel("claude-haiku-4-5-20251001") {
		t.Error("expected IsHaikuModel=true for claude-haiku-4-5-20251001")
	}
}

func TestIsHaikuModel_Opus(t *testing.T) {
	t.Parallel()
	if IsHaikuModel("claude-opus-4-6") {
		t.Error("expected IsHaikuModel=false for claude-opus-4-6")
	}
}
