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

const messagesPath = "/v1/messages"

func TestIsClaudeCodeClient_UAMismatch_AlwaysFalse(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "curl/7.88.1")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Beta", BetaClaudeCode)

	userID := "user_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" + "_account__session_abc-123"
	body := buildTestBody(t, "You are Claude Code, Anthropic's official CLI for Claude.", userID)

	if IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected false when UA does not match, even with all other signals")
	}
}

func TestIsClaudeCodeClient_NonMessagesPath_UAOnly(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")

	body := buildTestBody(t, nil, "")

	if !IsClaudeCodeClient(headers, body, "/v1/count_tokens") {
		t.Error("expected true for non-messages path with UA match")
	}
}

func TestIsClaudeCodeClient_HaikuProbe(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")

	body, _ := json.Marshal(map[string]interface{}{
		"model":      "claude-haiku-4-5",
		"max_tokens": 1,
		"stream":     false,
	})

	if !IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected true for Haiku probe (max_tokens=1, haiku, !stream)")
	}
}

func TestIsClaudeCodeClient_HaikuProbe_StreamTrue(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")

	body, _ := json.Marshal(map[string]interface{}{
		"model":      "claude-haiku-4-5",
		"max_tokens": 1,
		"stream":     true,
	})

	// stream=true means this is NOT a haiku probe, and with no other signals → false
	if IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected false for Haiku probe with stream=true and no other signals")
	}
}

func TestIsClaudeCodeClient_AllSignals(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Beta", BetaClaudeCode+",adaptive-thinking-2026-01-28")

	userID := "user_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" + "_account__session_abc-123"
	body := buildTestBody(t, "You are Claude Code, Anthropic's official CLI for Claude. Here are instructions.", userID)

	if !IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected true for full Claude Code request with all signals")
	}
}

func TestIsClaudeCodeClient_TwoOfFourSignals(t *testing.T) {
	t.Parallel()
	// UA matches (gate passes), then X-App + Beta = 2 of 4 → true
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Beta", BetaClaudeCode)

	body := buildTestBody(t, "You are a helpful assistant.", "")

	if !IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected true for UA + 2 of 4 signals (X-App + Beta)")
	}
}

func TestIsClaudeCodeClient_OneOfFourSignals(t *testing.T) {
	t.Parallel()
	// UA matches (gate passes), but only X-App = 1 of 4 → false
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")

	// Use a system prompt that won't match any Claude Code prefix via Dice coefficient.
	body := buildTestBody(t, "Generate a JSON schema for the API.", "")

	if IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected false for UA + only 1 of 4 signals")
	}
}

func TestIsClaudeCodeClient_ZeroOfFourSignals(t *testing.T) {
	t.Parallel()
	// UA matches (gate passes), but 0 of 4 additional signals → false
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")

	body := buildTestBody(t, "Generate a JSON schema for the API.", "")

	if IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected false for UA + 0 of 4 signals on messages path")
	}
}

func TestIsClaudeCodeClient_CurlRequest(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "curl/7.88.1")

	body := buildTestBody(t, "You are a helpful assistant.", "")

	if IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected false for curl request")
	}
}

func TestDiceCoefficient_Identical(t *testing.T) {
	t.Parallel()
	got := DiceCoefficient("hello world", "hello world")
	if got != 1.0 {
		t.Errorf("expected 1.0 for identical strings, got %f", got)
	}
}

func TestDiceCoefficient_NoOverlap(t *testing.T) {
	t.Parallel()
	got := DiceCoefficient("abc", "xyz")
	if got != 0.0 {
		t.Errorf("expected 0.0 for no-overlap strings, got %f", got)
	}
}

func TestIsClaudeCodeClient_UserIDFormatB(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")

	// Format B: user_{hex}_account_{uuid}_session_{uuid}
	userID := "user_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" + "_account_550e8400-e29b-41d4-a716-446655440000_session_abc-123"
	body := buildTestBody(t, "You are Claude Code, Anthropic's official CLI for Claude.", userID)

	// X-App (1) + user_id (1) + system_prompt (1) = 3 of 5 → true
	if !IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected true for Format B user_id with sufficient signals")
	}
}

func TestIsClaudeCodeClient_AnthropicVersionSignal(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Version", "2023-06-01")

	// X-App (1) + Anthropic-Version (1) = 2 of 5 → true
	body := buildTestBody(t, "Generate a JSON schema.", "")

	if !IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected true for UA + X-App + Anthropic-Version (2 of 5)")
	}
}

func TestDiceCoefficient_SimilarStrings(t *testing.T) {
	t.Parallel()
	a := "You are Claude Code, Anthropic's official CLI"
	b := "You are Claude Code, Anthropic's CLI tool"
	got := DiceCoefficient(a, b)
	if got < 0.5 {
		t.Errorf("expected dice >= 0.5 for similar strings, got %f", got)
	}
}

func TestIsClaudeCodeClient_JSONFormatUserID(t *testing.T) {
	t.Parallel()
	// CLI >= 2.1.78 sends user_id as JSON object
	body := []byte(`{
        "model": "claude-opus-4-5",
        "max_tokens": 100,
        "stream": true,
        "metadata": {
            "user_id": {"device_id": "aabbcc", "session_id": "550e8400-e29b-41d4-a716-446655440000"}
        },
        "system": "You are Claude Code, Anthropic's official CLI for Claude, version 2.0"
    }`)
	headers := http.Header{
		"User-Agent":        []string{"claude-cli/2.1.78 (darwin)"},
		"Anthropic-Version": []string{"2023-06-01"},
	}
	result := IsClaudeCodeClient(headers, body, "/v1/messages")
	if !result {
		t.Error("expected JSON-format user_id to be recognized as CC client")
	}
}

func TestIsClaudeCodeClient_ArraySystemWithBillingHeader(t *testing.T) {
	t.Parallel()
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.76 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Version", "2023-06-01")

	userID := "user_" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2" + "_account__session_abc-123"

	// Simulate v2.1.66+ format: billing header is the first block,
	// Claude Code system prompt is in a later block.
	system := []interface{}{
		map[string]interface{}{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.76; cc_entrypoint=cli; cch=abc12"},
		map[string]interface{}{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude. Here are instructions."},
	}

	body := buildTestBody(t, system, userID)

	// Should detect: X-App(1) + Anthropic-Version(1) + user_id(1) + system_prompt(1) = 4 of 5
	if !IsClaudeCodeClient(headers, body, messagesPath) {
		t.Error("expected true for array system with billing header prefix block and CC prompt in later block")
	}
}
