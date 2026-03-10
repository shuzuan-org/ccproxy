package disguise

import (
	"encoding/json"
	"net/http"
	"testing"
)

// buildTestBody builds a JSON request body for testing.
func buildTestBody(t *testing.T, system interface{}, userID string) []byte {
	t.Helper()
	body := map[string]interface{}{
		"model": "claude-opus-4-6",
	}
	if system != nil {
		body["system"] = system
	}
	if userID != "" {
		body["metadata"] = map[string]string{"user_id": userID}
	}
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("failed to marshal body: %v", err)
	}
	return b
}

func TestIsClaudeCodeClient_AllSignals(t *testing.T) {
	// Real Claude Code request with all 5 signals.
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Beta", BetaClaudeCode+",adaptive-thinking-2026-01-28")

	userID := "user_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" + "_account__session_abc-123"
	body := buildTestBody(t, "You are Claude Code, Anthropic's official CLI for Claude. Here are instructions.", userID)

	if !IsClaudeCodeClient(headers, body) {
		t.Error("expected IsClaudeCodeClient=true for full Claude Code request")
	}
}

func TestIsClaudeCodeClient_CurlRequest(t *testing.T) {
	// curl request with no signals.
	headers := http.Header{}
	headers.Set("User-Agent", "curl/7.88.1")

	body := buildTestBody(t, "You are a helpful assistant.", "")

	if IsClaudeCodeClient(headers, body) {
		t.Error("expected IsClaudeCodeClient=false for curl request")
	}
}

func TestIsClaudeCodeClient_OnlyUA(t *testing.T) {
	// Only User-Agent matches (1 signal) — should be false.
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")

	body := buildTestBody(t, "You are a helpful assistant.", "")

	if IsClaudeCodeClient(headers, body) {
		t.Error("expected IsClaudeCodeClient=false when only 1 signal matches")
	}
}

func TestIsClaudeCodeClient_ThreeSignals(t *testing.T) {
	// UA + X-App + beta (3 signals) — should be true.
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Beta", BetaClaudeCode)

	body := buildTestBody(t, "You are a helpful assistant.", "")

	if !IsClaudeCodeClient(headers, body) {
		t.Error("expected IsClaudeCodeClient=true for UA+X-App+beta (3 signals)")
	}
}

func TestDiceCoefficient_Identical(t *testing.T) {
	got := DiceCoefficient("hello world", "hello world")
	if got != 1.0 {
		t.Errorf("expected 1.0 for identical strings, got %f", got)
	}
}

func TestDiceCoefficient_NoOverlap(t *testing.T) {
	got := DiceCoefficient("abc", "xyz")
	if got != 0.0 {
		t.Errorf("expected 0.0 for no-overlap strings, got %f", got)
	}
}

func TestDiceCoefficient_SimilarStrings(t *testing.T) {
	// "You are Claude Code" vs "You are Claude" should have high similarity.
	a := "You are Claude Code, Anthropic's official CLI"
	b := "You are Claude Code, Anthropic's CLI tool"
	got := DiceCoefficient(a, b)
	if got < 0.5 {
		t.Errorf("expected dice >= 0.5 for similar strings, got %f", got)
	}
}
