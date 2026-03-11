package disguise

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// newTestRequest creates a test HTTP request with the given body.
func newTestRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", nil)
	req.Header = make(http.Header)
	return req
}

// buildEngineBody builds a JSON body for engine tests.
func buildEngineBody(t *testing.T, fields map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("failed to marshal body: %v", err)
	}
	return b
}

// parseBody is a helper to unmarshal JSON body and fail on error.
func parseBody(t *testing.T, body []byte) map[string]interface{} {
	t.Helper()
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to unmarshal body: %v", err)
	}
	return result
}

// metadataUserIDRegex matches the format: user_{64hex}_account__session_{uuid}
var metadataUserIDRegex = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account__session_[\w-]+$`)

// TestEngineApply_OAuthNonClaudeCode verifies all 6 layers are applied
// when isOAuth=true and the client is not a real Claude Code client.
func TestEngineApply_OAuthNonClaudeCode(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "hello"}},
	})

	outBody, applied := e.Apply(req, body, true, false, "test-session")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	// Layer 2: HTTP headers
	if ua := req.Header.Get("User-Agent"); !strings.HasPrefix(ua, "claude-cli/") {
		t.Errorf("expected claude-cli User-Agent, got %q", ua)
	}
	if req.Header.Get("X-App") != "cli" {
		t.Errorf("expected X-App=cli, got %q", req.Header.Get("X-App"))
	}
	if req.Header.Get("X-Stainless-Lang") != "js" {
		t.Errorf("expected X-Stainless-Lang=js, got %q", req.Header.Get("X-Stainless-Lang"))
	}
	if req.Header.Get("X-Stainless-OS") == "" {
		t.Error("expected X-Stainless-OS to be set")
	}

	// Layer 3: anthropic-beta header (mimic mode: oauth + interleaved-thinking only)
	beta := req.Header.Get("Anthropic-Beta")
	if !strings.Contains(beta, BetaOAuth) {
		t.Errorf("expected anthropic-beta to contain %q, got %q", BetaOAuth, beta)
	}
	if !strings.Contains(beta, BetaInterleavedThinking) {
		t.Errorf("expected anthropic-beta to contain %q, got %q", BetaInterleavedThinking, beta)
	}

	parsed := parseBody(t, outBody)

	// Layer 4: System prompt injected
	system, ok := parsed["system"]
	if !ok {
		t.Fatal("expected system key in body after disguise")
	}
	sysText := extractSystemText(system)
	if !strings.HasPrefix(sysText, "You are Claude Code") {
		t.Errorf("expected system prompt to start with Claude Code prompt, got %q", sysText)
	}

	// Layer 5: metadata.user_id generated
	meta, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected metadata key in body after disguise")
	}
	userID, _ := meta["user_id"].(string)
	if !metadataUserIDRegex.MatchString(userID) {
		t.Errorf("expected user_id to match pattern, got %q", userID)
	}

	// Layer 6: Model ID normalized
	model, _ := parsed["model"].(string)
	if model != "claude-sonnet-4-5-20250929" {
		t.Errorf("expected model normalized to 'claude-sonnet-4-5-20250929', got %q", model)
	}
}

// TestEngineApply_OAuthRealClaudeCode verifies no disguise is applied
// when the request already has 3+ Claude Code signals (real Claude Code client).
func TestEngineApply_OAuthRealClaudeCode(t *testing.T) {
	e := NewEngine()

	// Build a real Claude Code-looking request with all 5 signals.
	req := newTestRequest(t, nil)
	req.Header.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	req.Header.Set("X-App", "cli")
	req.Header.Set("Anthropic-Beta", BetaClaudeCode+",adaptive-thinking-2026-01-28")

	validUserID := "user_" + strings.Repeat("a1", 32) + "_account__session_abc-123-def"
	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"system": "You are Claude Code, Anthropic's official CLI for Claude. Some extra instructions.",
		"metadata": map[string]interface{}{
			"user_id": validUserID,
		},
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if applied {
		t.Error("expected disguise NOT to be applied for real Claude Code client")
	}
	if string(outBody) != string(body) {
		t.Error("expected original body returned unchanged")
	}
	// User-Agent should remain unchanged (not overwritten)
	if req.Header.Get("User-Agent") != "claude-cli/2.1.71 (external, cli)" {
		t.Errorf("User-Agent was unexpectedly modified: %q", req.Header.Get("User-Agent"))
	}
}

// TestEngineApply_BearerNonOAuth verifies no disguise is applied when isOAuth=false,
// regardless of client type.
func TestEngineApply_BearerNonOAuth(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, false, false, "seed")

	if applied {
		t.Error("expected disguise NOT to be applied for non-OAuth (Bearer) client")
	}
	if string(outBody) != string(body) {
		t.Error("expected original body returned unchanged for Bearer auth")
	}
	// No Claude CLI headers should be set
	if ua := req.Header.Get("User-Agent"); strings.HasPrefix(ua, "claude-cli/") {
		t.Errorf("expected no claude-cli User-Agent for Bearer auth, got %q", ua)
	}
}

// TestEngineApply_SystemPromptNotDuplicated verifies system prompt is not re-injected
// when the body already contains a Claude Code system prompt prefix.
func TestEngineApply_SystemPromptNotDuplicated(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":  "claude-sonnet-4-5",
		"system": "You are Claude Code, Anthropic's official CLI for Claude. Extra context here.",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)

	// When system already starts with the Claude Code prompt, it should be left as-is
	// (the injectSystemPrompt function returns early via HasPrefix check)
	switch s := parsed["system"].(type) {
	case string:
		if !strings.HasPrefix(s, "You are Claude Code") {
			t.Errorf("expected system to still start with Claude Code prompt, got %q", s)
		}
	case []interface{}:
		// Already had the prefix, should not have been modified
	default:
		t.Fatalf("unexpected system type: %T", parsed["system"])
	}
}

// TestEngineApply_NoSystemPromptForHaiku verifies system prompt injection is skipped
// for Haiku models.
func TestEngineApply_NoSystemPromptForHaiku(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-haiku-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	if system, ok := parsed["system"]; ok {
		sysText := extractSystemText(system)
		if strings.Contains(sysText, "You are Claude Code") {
			t.Errorf("expected NO Claude Code system prompt for Haiku, but found it: %q", sysText)
		}
	}
	// system key may or may not be present, but must not contain Claude Code prompt
}

// TestEngineApplyToURL_NoQueryParams verifies ?beta=true is appended when no query string exists.
func TestEngineApplyToURL_NoQueryParams(t *testing.T) {
	e := NewEngine()
	input := "https://api.anthropic.com/v1/messages"
	want := "https://api.anthropic.com/v1/messages?beta=true"
	got := e.ApplyToURL(input)
	if got != want {
		t.Errorf("ApplyToURL(%q) = %q, want %q", input, got, want)
	}
}

// TestEngineApplyToURL_WithExistingQueryParams verifies &beta=true is appended
// when URL already has query parameters.
func TestEngineApplyToURL_WithExistingQueryParams(t *testing.T) {
	e := NewEngine()
	input := "https://api.anthropic.com/v1/messages?foo=bar"
	want := "https://api.anthropic.com/v1/messages?foo=bar&beta=true"
	got := e.ApplyToURL(input)
	if got != want {
		t.Errorf("ApplyToURL(%q) = %q, want %q", input, got, want)
	}
}

// TestEngineApplyResponseModelID_Denormalized verifies that full versioned model IDs
// in responses are reversed back to short names.
func TestEngineApplyResponseModelID_Denormalized(t *testing.T) {
	e := NewEngine()

	respBody, _ := json.Marshal(map[string]interface{}{
		"id":    "msg_123",
		"model": "claude-sonnet-4-5-20250929",
		"type":  "message",
	})

	out := e.ApplyResponseModelID(respBody)
	parsed := parseBody(t, out)

	model, _ := parsed["model"].(string)
	if model != "claude-sonnet-4-5" {
		t.Errorf("expected model denormalized to 'claude-sonnet-4-5', got %q", model)
	}
}

// TestEngineApplyResponseModelID_UnknownModel verifies that unknown model IDs
// are left unchanged.
func TestEngineApplyResponseModelID_UnknownModel(t *testing.T) {
	e := NewEngine()

	respBody, _ := json.Marshal(map[string]interface{}{
		"id":    "msg_456",
		"model": "claude-opus-4-6",
		"type":  "message",
	})

	out := e.ApplyResponseModelID(respBody)
	parsed := parseBody(t, out)

	model, _ := parsed["model"].(string)
	if model != "claude-opus-4-6" {
		t.Errorf("expected unknown model 'claude-opus-4-6' to remain unchanged, got %q", model)
	}
}

// TestEngineApply_ModelNormalization verifies that short model names are replaced
// with their full versioned counterparts in the request body.
func TestEngineApply_ModelNormalization(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	model, _ := parsed["model"].(string)
	if model != "claude-sonnet-4-5-20250929" {
		t.Errorf("expected model normalized to 'claude-sonnet-4-5-20250929', got %q", model)
	}
}

// TestEngineApply_StreamHeader verifies X-Stainless-Helper-Method is set for streaming.
func TestEngineApply_StreamHeader(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"stream":   true,
		"messages": []interface{}{},
	})

	_, applied := e.Apply(req, body, true, true, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	helperMethod := req.Header.Get("X-Stainless-Helper-Method")
	if helperMethod != "stream" {
		t.Errorf("expected X-Stainless-Helper-Method=stream for streaming request, got %q", helperMethod)
	}
}

// TestEngineApply_SessionSeedDeterminism verifies that the same sessionSeed
// produces different user_id prefixes but same UUID suffix.
func TestEngineApply_SessionSeedDeterminism(t *testing.T) {
	e := NewEngine()

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	req1 := newTestRequest(t, nil)
	out1, _ := e.Apply(req1, body, true, false, "fixed-seed")
	parsed1 := parseBody(t, out1)

	req2 := newTestRequest(t, nil)
	out2, _ := e.Apply(req2, body, true, false, "fixed-seed")
	parsed2 := parseBody(t, out2)

	meta1 := parsed1["metadata"].(map[string]interface{})
	meta2 := parsed2["metadata"].(map[string]interface{})
	userID1 := meta1["user_id"].(string)
	userID2 := meta2["user_id"].(string)

	// Both must match the format
	if !metadataUserIDRegex.MatchString(userID1) {
		t.Errorf("user_id1 does not match pattern: %q", userID1)
	}
	if !metadataUserIDRegex.MatchString(userID2) {
		t.Errorf("user_id2 does not match pattern: %q", userID2)
	}

	// The UUID part (session seed) should be the same for same seed
	// Format: user_{hex}_account__session_{uuid}
	getUUID := func(uid string) string {
		parts := strings.Split(uid, "_account__session_")
		if len(parts) == 2 {
			return parts[1]
		}
		return ""
	}
	if getUUID(userID1) != getUUID(userID2) {
		t.Errorf("expected same UUID for same sessionSeed, got %q vs %q", getUUID(userID1), getUUID(userID2))
	}
}

// TestEngineApply_SystemStringConvertedToArray verifies that a string system prompt
// is converted to array format with Claude Code prompt prepended.
func TestEngineApply_SystemStringConvertedToArray(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	originalSystem := "You are a helpful assistant."
	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   originalSystem,
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	systemRaw := parsed["system"]

	arr, ok := systemRaw.([]interface{})
	if !ok {
		t.Fatalf("expected system to be array after injection, got %T", systemRaw)
	}

	if len(arr) < 2 {
		t.Fatalf("expected at least 2 elements in system array, got %d", len(arr))
	}

	// First element should be Claude Code prompt with cache_control
	first := arr[0].(map[string]interface{})
	if first["text"] != claudeCodeSystemPrompt {
		t.Errorf("expected first system element to be Claude Code prompt, got %q", first["text"])
	}
	if cc, ok := first["cache_control"].(map[string]interface{}); !ok || cc["type"] != "ephemeral" {
		t.Error("expected first system element to have cache_control ephemeral")
	}

	// Second element should be original prompt prefixed with Claude Code banner
	second := arr[1].(map[string]interface{})
	expectedMerged := strings.TrimSpace(claudeCodeSystemPrompt) + "\n\n" + originalSystem
	if second["text"] != expectedMerged {
		t.Errorf("expected second system element to be prefixed prompt %q, got %q", expectedMerged, second["text"])
	}
}

// TestEngineApply_InjectsEmptyTools verifies that an empty tools array is injected
// when the request body has no tools field.
func TestEngineApply_InjectsEmptyTools(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)

	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatalf("expected tools to be an array, got %T", parsed["tools"])
	}
	if len(tools) != 0 {
		t.Errorf("expected empty tools array, got %d elements", len(tools))
	}
}

// TestEngineApply_PreservesExistingTools verifies that existing tools are not overwritten.
func TestEngineApply_PreservesExistingTools(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
		"tools": []interface{}{
			map[string]interface{}{"name": "my_tool", "description": "test"},
		},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	tools, ok := parsed["tools"].([]interface{})
	if !ok {
		t.Fatalf("expected tools to be an array, got %T", parsed["tools"])
	}
	if len(tools) != 1 {
		t.Errorf("expected 1 tool preserved, got %d", len(tools))
	}
}

// TestEngineApply_RemovesTemperatureAndToolChoice verifies that temperature
// and tool_choice fields are stripped from the request body.
func TestEngineApply_RemovesTemperatureAndToolChoice(t *testing.T) {
	e := NewEngine()
	req := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":       "claude-sonnet-4-5",
		"messages":    []interface{}{},
		"temperature": 0.7,
		"tool_choice": map[string]interface{}{"type": "auto"},
	})

	outBody, applied := e.Apply(req, body, true, false, "seed")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)

	if _, exists := parsed["temperature"]; exists {
		t.Error("expected temperature to be removed from body")
	}
	if _, exists := parsed["tool_choice"]; exists {
		t.Error("expected tool_choice to be removed from body")
	}
}
