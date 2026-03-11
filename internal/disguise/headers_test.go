package disguise

import (
	"net/http"
	"strings"
	"testing"
)

func TestApplyHeaders_AllDefaultHeaders(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}
	ApplyHeaders(req, false)

	// Verify all 11 default headers are set.
	for k, v := range DefaultHeaders {
		if got := req.Header.Get(k); got != v {
			t.Errorf("header %q: expected %q, got %q", k, v, got)
		}
	}

	// Also verify Accept and Anthropic-Version.
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept: expected application/json, got %q", got)
	}
	if got := req.Header.Get("Anthropic-Version"); got != "2023-06-01" {
		t.Errorf("Anthropic-Version: expected 2023-06-01, got %q", got)
	}
}

func TestApplyHeaders_StreamAddsHelperMethod(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}
	ApplyHeaders(req, true)

	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "stream" {
		t.Errorf("expected X-Stainless-Helper-Method=stream, got %q", got)
	}
}

func TestApplyHeaders_NoStreamNoHelperMethod(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header = http.Header{}
	ApplyHeaders(req, false)

	if got := req.Header.Get("X-Stainless-Helper-Method"); got != "" {
		t.Errorf("expected X-Stainless-Helper-Method to be absent, got %q", got)
	}
}

func TestBetaHeader_OpusWithOAuth(t *testing.T) {
	result := BetaHeader("claude-opus-4-6", false, true)
	// Mimic mode: oauth + interleaved-thinking only (no claude-code per sub2api)
	expected := BetaOAuth + "," + BetaInterleavedThinking
	if result != expected {
		t.Errorf("Opus+OAuth: expected %q, got %q", expected, result)
	}
}

func TestBetaHeader_HaikuWithOAuth(t *testing.T) {
	result := BetaHeader("claude-haiku-4-5-20251001", false, true)
	expected := BetaOAuth + "," + BetaInterleavedThinking
	if result != expected {
		t.Errorf("Haiku+OAuth: expected %q, got %q", expected, result)
	}
}

func TestBetaHeader_SonnetNoOAuth(t *testing.T) {
	result := BetaHeader("claude-sonnet-4-5", false, false)
	if strings.Contains(result, BetaOAuth) {
		t.Errorf("Sonnet+APIKey: expected no oauth token, got %q", result)
	}
	if result != BetaInterleavedThinking {
		t.Errorf("Sonnet+APIKey: expected %q, got %q", BetaInterleavedThinking, result)
	}
}

func TestCountTokensBetaHeader_WithOAuth(t *testing.T) {
	result := CountTokensBetaHeader(true)
	if !strings.Contains(result, BetaTokenCounting) {
		t.Errorf("expected token-counting in %q", result)
	}
	if !strings.Contains(result, BetaOAuth) {
		t.Errorf("expected oauth in %q", result)
	}
	if !strings.Contains(result, BetaClaudeCode) {
		t.Errorf("expected claude-code in %q", result)
	}
}

func TestIsHaikuModel_Haiku(t *testing.T) {
	if !IsHaikuModel("claude-haiku-4-5-20251001") {
		t.Error("expected IsHaikuModel=true for claude-haiku-4-5-20251001")
	}
}

func TestIsHaikuModel_Opus(t *testing.T) {
	if IsHaikuModel("claude-opus-4-6") {
		t.Error("expected IsHaikuModel=false for claude-opus-4-6")
	}
}
