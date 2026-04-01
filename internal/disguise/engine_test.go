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

// newTestRequestPair creates an origReq (for detection) and upstreamReq (for modification).
func newTestRequestPair(t *testing.T) (origReq, upstreamReq *http.Request) {
	t.Helper()
	return newTestRequest(t, nil), newTestRequest(t, nil)
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

// newTestEngine creates a test Engine with a temp data directory.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	return NewEngine(t.TempDir())
}

// TestEngineApply_OAuthNonClaudeCode verifies all layers are applied
// when the client is not a real Claude Code client.
func TestEngineApply_OAuthNonClaudeCode(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{map[string]interface{}{"role": "user", "content": "hello"}},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "test-session", "acct-1")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	// Layer 2: HTTP headers (set on upstreamReq)
	if ua := upstreamReq.Header.Get("User-Agent"); !strings.HasPrefix(ua, "claude-cli/") {
		t.Errorf("expected claude-cli User-Agent, got %q", ua)
	}
	if upstreamReq.Header["x-app"] == nil || upstreamReq.Header["x-app"][0] != "cli" {
		t.Errorf("expected x-app=cli, got %q", upstreamReq.Header["x-app"])
	}
	if upstreamReq.Header.Get("X-Stainless-Lang") != "js" {
		t.Errorf("expected X-Stainless-Lang=js, got %q", upstreamReq.Header.Get("X-Stainless-Lang"))
	}
	if upstreamReq.Header.Get("X-Stainless-OS") == "" {
		t.Error("expected X-Stainless-OS to be set")
	}

	// Layer 3: anthropic-beta header (non-Haiku without tools → MessageBetaHeaderNoTools)
	beta := upstreamReq.Header["anthropic-beta"]
	if len(beta) == 0 || beta[0] != MessageBetaHeaderNoTools {
		t.Errorf("expected anthropic-beta=%q, got %q", MessageBetaHeaderNoTools, beta)
	}

	parsed := parseBody(t, outBody)

	// Layer 4: System prompt injected
	system, ok := parsed["system"]
	if !ok {
		t.Fatal("expected system key in body after disguise")
	}
	allTexts := extractAllSystemTexts(system)
	sysText := ""
	if len(allTexts) > 0 {
		sysText = allTexts[0]
	}
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

// TestEngineApply_OAuthNonClaudeCode_WithTools verifies tools trigger DefaultBetaHeader.
func TestEngineApply_OAuthNonClaudeCode_WithTools(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
		"tools":    []interface{}{map[string]interface{}{"name": "my_tool"}},
	})

	_, applied := e.Apply(origReq, upstreamReq, body, false, "test-session", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	beta := upstreamReq.Header["anthropic-beta"]
	if len(beta) == 0 || beta[0] != DefaultBetaHeader {
		t.Errorf("expected beta=%q for request with tools, got %q", DefaultBetaHeader, beta)
	}
}

// TestEngineApply_OAuthRealClaudeCode verifies that for real CC clients via OAuth:
// - applied=true (so handler appends ?beta=true)
// - beta header is supplemented with oauth token
// - metadata.user_id is rewritten (different from original)
// - model, system prompt, and other body fields are NOT modified
func TestEngineApply_OAuthRealClaudeCode(t *testing.T) {
	e := newTestEngine(t)

	// origReq has full Claude Code signals (User-Agent, X-App, Anthropic-Beta).
	origReq := newTestRequest(t, nil)
	origReq.Header.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	origReq.Header.Set("X-App", "cli")
	origReq.Header.Set("Anthropic-Beta", BetaClaudeCode+",adaptive-thinking-2026-01-28")

	// upstreamReq only has headers that proxy copies (Content-Type, Anthropic-Beta, etc.)
	upstreamReq := newTestRequest(t, nil)
	upstreamReq.Header.Set("Anthropic-Beta", BetaClaudeCode+",adaptive-thinking-2026-01-28")

	validUserID := "user_" + strings.Repeat("a1", 32) + "_account__session_abc-123-def"
	originalSystem := "You are Claude Code, Anthropic's official CLI for Claude. Some extra instructions."
	body := buildEngineBody(t, map[string]interface{}{
		"model":  "claude-sonnet-4-5",
		"system": originalSystem,
		"metadata": map[string]interface{}{
			"user_id": validUserID,
		},
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

	// Should be applied=true so handler appends ?beta=true
	if !applied {
		t.Error("expected applied=true for real CC client via OAuth")
	}

	// Beta header: should have oauth token supplemented
	betaVals := upstreamReq.Header["anthropic-beta"]
	beta := ""
	if len(betaVals) > 0 {
		beta = betaVals[0]
	}
	if !strings.Contains(beta, BetaOAuth) {
		t.Errorf("expected beta to contain %q, got %q", BetaOAuth, beta)
	}
	// Original beta tokens should be preserved
	if !strings.Contains(beta, BetaClaudeCode) {
		t.Errorf("expected original %q to be preserved, got %q", BetaClaudeCode, beta)
	}
	if !strings.Contains(beta, "adaptive-thinking-2026-01-28") {
		t.Errorf("expected original adaptive-thinking to be preserved, got %q", beta)
	}

	parsed := parseBody(t, outBody)

	// metadata.user_id should be rewritten (different from original)
	meta, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		t.Fatal("expected metadata in output body")
	}
	newUserID, _ := meta["user_id"].(string)
	if newUserID == validUserID {
		t.Error("expected user_id to be rewritten, got original value")
	}
	if !metadataUserIDRegex.MatchString(newUserID) {
		t.Errorf("rewritten user_id does not match expected format: %q", newUserID)
	}

	// Model should NOT be normalized (no full disguise)
	model, _ := parsed["model"].(string)
	if model != "claude-sonnet-4-5" {
		t.Errorf("expected model to remain unchanged as 'claude-sonnet-4-5', got %q", model)
	}

	// System prompt should NOT be modified
	systemText, _ := parsed["system"].(string)
	if systemText != originalSystem {
		t.Errorf("expected system prompt unchanged, got %q", systemText)
	}

	// No tools injection, no temperature/tool_choice removal
	if _, exists := parsed["tools"]; exists {
		t.Error("expected no tools field injection for CC client path")
	}
}

// TestEngineApply_OAuthRealClaudeCode_Deterministic verifies that the same
// CC client request with the same seed produces the same rewritten user_id.
func TestEngineApply_OAuthRealClaudeCode_Deterministic(t *testing.T) {
	e := newTestEngine(t)

	validUserID := "user_" + strings.Repeat("a1", 32) + "_account__session_abc-123-def"
	makeReq := func() (*http.Request, *http.Request, []byte) {
		origReq := newTestRequest(t, nil)
		origReq.Header.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
		origReq.Header.Set("X-App", "cli")
		origReq.Header.Set("Anthropic-Beta", BetaClaudeCode+","+BetaInterleavedThinking)
		upstreamReq := newTestRequest(t, nil)
		upstreamReq.Header.Set("Anthropic-Beta", BetaClaudeCode+","+BetaInterleavedThinking)
		body := buildEngineBody(t, map[string]interface{}{
			"model":    "claude-sonnet-4-5",
			"system":   "You are Claude Code, Anthropic's official CLI for Claude.",
			"metadata": map[string]interface{}{"user_id": validUserID},
			"messages": []interface{}{},
		})
		return origReq, upstreamReq, body
	}

	origReq1, upReq1, body1 := makeReq()
	out1, _ := e.Apply(origReq1, upReq1, body1, false, "same-seed", "acct-1")
	parsed1 := parseBody(t, out1)

	origReq2, upReq2, body2 := makeReq()
	out2, _ := e.Apply(origReq2, upReq2, body2, false, "same-seed", "acct-1")
	parsed2 := parseBody(t, out2)

	uid1 := parsed1["metadata"].(map[string]interface{})["user_id"].(string)
	uid2 := parsed2["metadata"].(map[string]interface{})["user_id"].(string)
	if uid1 != uid2 {
		t.Errorf("expected deterministic user_id, got %q vs %q", uid1, uid2)
	}
}

// TestEngineApply_SystemPromptNotDuplicated verifies system prompt is not re-injected
// when the body already contains a Claude Code system prompt prefix.
func TestEngineApply_SystemPromptNotDuplicated(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   "You are Claude Code, Anthropic's official CLI for Claude. Extra context here.",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)

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
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-haiku-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	if system, ok := parsed["system"]; ok {
		for _, sysText := range extractAllSystemTexts(system) {
			if strings.Contains(sysText, "You are Claude Code") {
				t.Errorf("expected NO Claude Code system prompt for Haiku, but found it: %q", sysText)
			}
		}
	}
}

// TestEngineApplyToURL_NoQueryParams verifies ?beta=true is appended when no query string exists.
func TestEngineApplyToURL_NoQueryParams(t *testing.T) {
	e := newTestEngine(t)
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
	e := newTestEngine(t)
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
	e := newTestEngine(t)

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
	e := newTestEngine(t)

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
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

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
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"stream":   true,
		"messages": []interface{}{},
	})

	_, applied := e.Apply(origReq, upstreamReq, body, true, "seed", "acct-1")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	helperMethod := ""
	if v := upstreamReq.Header["x-stainless-helper-method"]; len(v) > 0 {
		helperMethod = v[0]
	}
	if helperMethod != "stream" {
		t.Errorf("expected x-stainless-helper-method=stream for streaming request, got %q", helperMethod)
	}
}

// TestEngineApply_PerAccountFingerprint verifies that different accounts get different fingerprints.
func TestEngineApply_PerAccountFingerprint(t *testing.T) {
	e := newTestEngine(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	_, upstreamReq1 := newTestRequestPair(t)
	origReq1 := newTestRequest(t, nil)
	e.Apply(origReq1, upstreamReq1, body, false, "seed", "acct-1")

	_, upstreamReq2 := newTestRequestPair(t)
	origReq2 := newTestRequest(t, nil)
	e.Apply(origReq2, upstreamReq2, body, false, "seed", "acct-2")

	// Different accounts should potentially have different User-Agent values
	// (they're random, so could occasionally match, but ClientID will differ)
	ua1 := upstreamReq1.Header.Get("User-Agent")
	ua2 := upstreamReq2.Header.Get("User-Agent")
	if ua1 == "" || ua2 == "" {
		t.Error("expected User-Agent to be set for both accounts")
	}

	// Same account should get the same fingerprint
	_, upstreamReq3 := newTestRequestPair(t)
	origReq3 := newTestRequest(t, nil)
	e.Apply(origReq3, upstreamReq3, body, false, "seed", "acct-1")
	ua3 := upstreamReq3.Header.Get("User-Agent")
	if ua1 != ua3 {
		t.Errorf("same account should get same UA: %q vs %q", ua1, ua3)
	}
}

// TestEngineApply_SessionMasking verifies that same account gets same session UUID.
func TestEngineApply_SessionMasking(t *testing.T) {
	e := newTestEngine(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	origReq1, upstreamReq1 := newTestRequestPair(t)
	out1, _ := e.Apply(origReq1, upstreamReq1, body, false, "seed", "acct-1")
	parsed1 := parseBody(t, out1)

	origReq2, upstreamReq2 := newTestRequestPair(t)
	out2, _ := e.Apply(origReq2, upstreamReq2, body, false, "seed", "acct-1")
	parsed2 := parseBody(t, out2)

	getSession := func(p map[string]interface{}) string {
		meta := p["metadata"].(map[string]interface{})
		uid := meta["user_id"].(string)
		parts := strings.SplitN(uid, "_account__session_", 2)
		if len(parts) == 2 {
			return parts[1]
		}
		return ""
	}

	s1 := getSession(parsed1)
	s2 := getSession(parsed2)
	if s1 != s2 {
		t.Errorf("same account should have same masked session UUID: %q vs %q", s1, s2)
	}

	// Different account should have different session UUID
	origReq3, upstreamReq3 := newTestRequestPair(t)
	out3, _ := e.Apply(origReq3, upstreamReq3, body, false, "seed", "acct-2")
	parsed3 := parseBody(t, out3)
	s3 := getSession(parsed3)
	if s1 == s3 {
		t.Error("different accounts should have different masked session UUIDs")
	}
}

// TestEngineApply_SystemStringConvertedToArray verifies that a string system prompt
// is converted to array format with Claude Code prompt prepended.
func TestEngineApply_SystemStringConvertedToArray(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	originalSystem := "You are a helpful assistant."
	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   originalSystem,
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

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

	// Second element should be the original prompt WITHOUT double-prefixing.
	// The Claude Code banner is already in the first element; duplicating it
	// in the second block would be incorrect.
	second := arr[1].(map[string]interface{})
	if second["text"] != originalSystem {
		t.Errorf("expected second system element to be original prompt %q, got %q", originalSystem, second["text"])
	}
}

// TestEngineApply_ArraySystemNoDuplicatePrefix verifies that when system is already an
// array, the Claude Code prompt is prepended as block 0 but the original blocks are
// NOT prefixed again (regression test for double-injection bug).
func TestEngineApply_ArraySystemNoDuplicatePrefix(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	originalText := "You are a helpful assistant."
	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"system": []interface{}{
			map[string]interface{}{"type": "text", "text": originalText},
		},
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	arr, ok := parsed["system"].([]interface{})
	if !ok {
		t.Fatalf("expected system to be array, got %T", parsed["system"])
	}

	if len(arr) != 2 {
		t.Fatalf("expected exactly 2 system blocks, got %d", len(arr))
	}

	// Block 0: injected Claude Code prompt
	first := arr[0].(map[string]interface{})
	if first["text"] != claudeCodeSystemPrompt {
		t.Errorf("expected block 0 to be Claude Code prompt, got %q", first["text"])
	}

	// Block 1: original text, NOT prefixed with Claude Code banner
	second := arr[1].(map[string]interface{})
	if second["text"] != originalText {
		t.Errorf("expected block 1 to be original text %q, got %q", originalText, second["text"])
	}
	if strings.Contains(second["text"].(string), "You are Claude Code") {
		t.Errorf("block 1 should not contain Claude Code prefix, got %q", second["text"])
	}
}

// TestEngineApply_InjectsEmptyTools verifies that an empty tools array is injected
// when the request body has no tools field.
func TestEngineApply_InjectsEmptyTools(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

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
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
		"tools": []interface{}{
			map[string]interface{}{"name": "my_tool", "description": "test"},
		},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

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
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":       "claude-sonnet-4-5",
		"messages":    []interface{}{},
		"temperature": 0.7,
		"tool_choice": map[string]interface{}{"type": "auto"},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")

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

// TestEngineApply_ThinkingCacheControlCleaned verifies thinking blocks have
// cache_control removed during disguise.
func TestEngineApply_ThinkingCacheControlCleaned(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"messages": []interface{}{
			map[string]interface{}{
				"role": "assistant",
				"content": []interface{}{
					map[string]interface{}{
						"type":          "thinking",
						"thinking":      "deep thought",
						"cache_control": map[string]interface{}{"type": "ephemeral"},
					},
					map[string]interface{}{
						"type":          "text",
						"text":          "response",
						"cache_control": map[string]interface{}{"type": "ephemeral"},
					},
				},
			},
		},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	messages := parsed["messages"].([]interface{})
	content := messages[0].(map[string]interface{})["content"].([]interface{})

	thinkBlock := content[0].(map[string]interface{})
	if _, has := thinkBlock["cache_control"]; has {
		t.Error("expected cache_control removed from thinking block")
	}

	textBlock := content[1].(map[string]interface{})
	if _, has := textBlock["cache_control"]; !has {
		t.Error("expected cache_control preserved on text block")
	}
}

// TestEngineApply_OpenCodeReplacement verifies that OpenCode system prompts
// are replaced with Claude Code prompts during disguise.
func TestEngineApply_OpenCodeReplacement(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   "You are OpenCode, the best coding agent on the planet.",
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)

	// After replacement, the system text should not contain "OpenCode".
	// Since the replaced text matches a CC prefix, it may remain as string
	// (injectSystemPromptInPlace returns early) or be converted to array.
	sysText := strings.Join(extractAllSystemTexts(parsed["system"]), " ")
	if strings.Contains(sysText, "OpenCode") {
		t.Errorf("expected OpenCode to be replaced, but found: %q", sysText)
	}
	if !strings.Contains(sysText, "Claude Code") {
		t.Errorf("expected Claude Code in system text, got: %q", sysText)
	}
}

// TestEngineApply_CacheControlLimit verifies that excess cache_control blocks
// are removed, respecting the maxCacheControlBlocks limit.
func TestEngineApply_CacheControlLimit(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	// Build a body with 6 cache_control blocks (> limit of 4)
	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"system": []interface{}{
			map[string]interface{}{
				"type":          "text",
				"text":          "You are Claude Code, Anthropic's official CLI for Claude.",
				"cache_control": map[string]interface{}{"type": "ephemeral"},
			},
			map[string]interface{}{
				"type":          "text",
				"text":          "Additional context.",
				"cache_control": map[string]interface{}{"type": "ephemeral"},
			},
		},
		"messages": []interface{}{
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type":          "text",
						"text":          "msg1",
						"cache_control": map[string]interface{}{"type": "ephemeral"},
					},
				},
			},
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type":          "text",
						"text":          "msg2",
						"cache_control": map[string]interface{}{"type": "ephemeral"},
					},
				},
			},
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type":          "text",
						"text":          "msg3",
						"cache_control": map[string]interface{}{"type": "ephemeral"},
					},
				},
			},
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type":          "text",
						"text":          "msg4",
						"cache_control": map[string]interface{}{"type": "ephemeral"},
					},
				},
			},
		},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)

	// Count remaining cache_control blocks
	count := 0
	if sysRaw, ok := parsed["system"].([]interface{}); ok {
		for _, item := range sysRaw {
			if m, ok := item.(map[string]interface{}); ok {
				if _, has := m["cache_control"]; has {
					count++
				}
			}
		}
	}
	if msgsRaw, ok := parsed["messages"].([]interface{}); ok {
		for _, msg := range msgsRaw {
			if msgMap, ok := msg.(map[string]interface{}); ok {
				if contentArr, ok := msgMap["content"].([]interface{}); ok {
					for _, block := range contentArr {
						if blockMap, ok := block.(map[string]interface{}); ok {
							if _, has := blockMap["cache_control"]; has {
								count++
							}
						}
					}
				}
			}
		}
	}

	if count > maxCacheControlBlocks {
		t.Errorf("expected at most %d cache_control blocks, got %d", maxCacheControlBlocks, count)
	}
}

// TestEngineApply_PassesThroughBillingSystemBlocks verifies that system blocks starting
// with "x-anthropic-billing-header" are passed through (not filtered) during disguise,
// aligned with sub2api's transparent forwarding behavior.
func TestEngineApply_PassesThroughBillingSystemBlocks(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"system": []interface{}{
			map[string]interface{}{"type": "text", "text": "x-anthropic-billing-header: some billing data"},
			map[string]interface{}{"type": "text", "text": "You are a helpful assistant."},
		},
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	parsed := parseBody(t, outBody)
	sysArr, ok := parsed["system"].([]interface{})
	if !ok {
		t.Fatalf("expected system to be array, got %T", parsed["system"])
	}

	// Billing block should be preserved (pass-through, not filtered).
	found := false
	for _, item := range sysArr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		text, _ := m["text"].(string)
		if strings.Contains(text, "x-anthropic-billing-header") {
			found = true
			break
		}
	}
	if !found {
		t.Error("billing block should be passed through (not filtered), but was not found in output")
	}
}

// TestEngineApply_PassesThroughBillingSystemBlocks_CCClient verifies billing blocks
// are passed through for real CC clients (aligned with sub2api transparent forwarding).
func TestEngineApply_PassesThroughBillingSystemBlocks_CCClient(t *testing.T) {
	e := newTestEngine(t)

	origReq := newTestRequest(t, nil)
	origReq.Header.Set("User-Agent", "claude-cli/2.1.71 (external, cli)")
	origReq.Header.Set("X-App", "cli")
	origReq.Header.Set("Anthropic-Beta", BetaClaudeCode+","+BetaInterleavedThinking)

	upstreamReq := newTestRequest(t, nil)
	upstreamReq.Header.Set("Anthropic-Beta", BetaClaudeCode+","+BetaInterleavedThinking)

	validUserID := "user_" + strings.Repeat("a1", 32) + "_account__session_abc-123"
	body := buildEngineBody(t, map[string]interface{}{
		"model": "claude-sonnet-4-5",
		"system": []interface{}{
			map[string]interface{}{"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
			map[string]interface{}{"type": "text", "text": "x-anthropic-billing-header: billing data"},
		},
		"metadata": map[string]interface{}{"user_id": validUserID},
		"messages": []interface{}{},
	})

	outBody, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected applied=true")
	}

	parsed := parseBody(t, outBody)
	sysArr, ok := parsed["system"].([]interface{})
	if !ok {
		t.Fatalf("expected system to be array, got %T", parsed["system"])
	}

	// Billing block should be preserved (pass-through, not filtered).
	found := false
	for _, item := range sysArr {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		text, _ := m["text"].(string)
		if strings.Contains(text, "x-anthropic-billing-header") {
			found = true
			break
		}
	}
	if !found {
		t.Error("billing block should be passed through (not filtered) for CC client, but was not found in output")
	}
}

// TestEngineApply_PassesThroughBillingSystemBlocks_StringType verifies that a string
// system field starting with billing prefix is passed through (not removed).
func TestEngineApply_PassesThroughBillingSystemBlocks_StringType(t *testing.T) {
	e := newTestEngine(t)
	origReq, upstreamReq := newTestRequestPair(t)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   "x-anthropic-billing-header: data",
		"messages": []interface{}{},
	})

	outBody, _ := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	parsed := parseBody(t, outBody)

	// Billing text should be preserved in the output system prompt array.
	sysText := strings.Join(extractAllSystemTexts(parsed["system"]), " ")
	if !strings.Contains(sysText, "x-anthropic-billing-header") {
		t.Errorf("billing string system should be passed through (not filtered), combined system: %q", sysText)
	}
}

// TestEngineApply_CountTokensBeta verifies that count_tokens requests use
// the correct beta header with token-counting beta.
func TestEngineApply_CountTokensBeta(t *testing.T) {
	e := newTestEngine(t)

	origReq := newTestRequest(t, nil)
	origReq.URL.Path = "/v1/messages/count_tokens"
	upstreamReq := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	_, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	beta := ""
	if v := upstreamReq.Header["anthropic-beta"]; len(v) > 0 {
		beta = v[0]
	}
	if !strings.Contains(beta, BetaTokenCounting) {
		t.Errorf("expected beta to contain %q for count_tokens, got %q", BetaTokenCounting, beta)
	}
	if !strings.Contains(beta, BetaClaudeCode) {
		t.Errorf("expected beta to contain %q for count_tokens, got %q", BetaClaudeCode, beta)
	}
}

// TestEngineApply_MergesClientBetas verifies that client-provided betas like
// context-1m are preserved and merged with required betas.
func TestEngineApply_MergesClientBetas(t *testing.T) {
	e := newTestEngine(t)

	origReq := newTestRequest(t, nil)
	origReq.Header.Set("Anthropic-Beta", BetaContext1M+","+BetaFastMode)
	upstreamReq := newTestRequest(t, nil)

	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"messages": []interface{}{},
	})

	_, applied := e.Apply(origReq, upstreamReq, body, false, "seed", "acct-1")
	if !applied {
		t.Fatal("expected disguise to be applied")
	}

	beta := ""
	if v := upstreamReq.Header["anthropic-beta"]; len(v) > 0 {
		beta = v[0]
	}
	// Client betas should be preserved
	if !strings.Contains(beta, BetaContext1M) {
		t.Errorf("expected beta to contain client %q, got %q", BetaContext1M, beta)
	}
	if !strings.Contains(beta, BetaFastMode) {
		t.Errorf("expected beta to contain client %q, got %q", BetaFastMode, beta)
	}
	// Required betas should be present
	if !strings.Contains(beta, BetaOAuth) {
		t.Errorf("expected beta to contain %q, got %q", BetaOAuth, beta)
	}
	if !strings.Contains(beta, BetaClaudeCode) {
		t.Errorf("expected beta to contain %q, got %q", BetaClaudeCode, beta)
	}
}

// TestEngineApply_LearnFingerprint verifies that fingerprint learning occurs
// when a real CC client is detected.
func TestEngineApply_LearnFingerprint(t *testing.T) {
	e := newTestEngine(t)

	origReq := newTestRequest(t, nil)
	origReq.Header.Set("User-Agent", "claude-cli/2.3.0 (external, cli)")
	origReq.Header.Set("X-App", "cli")
	origReq.Header.Set("Anthropic-Beta", BetaClaudeCode+","+BetaInterleavedThinking)
	origReq.Header.Set("X-Stainless-OS", "Darwin")
	origReq.Header.Set("X-Stainless-Arch", "arm64")

	upstreamReq := newTestRequest(t, nil)
	upstreamReq.Header.Set("Anthropic-Beta", BetaClaudeCode+","+BetaInterleavedThinking)

	validUserID := "user_" + strings.Repeat("a1", 32) + "_account__session_abc-123"
	body := buildEngineBody(t, map[string]interface{}{
		"model":    "claude-sonnet-4-5",
		"system":   "You are Claude Code, Anthropic's official CLI for Claude.",
		"metadata": map[string]interface{}{"user_id": validUserID},
		"messages": []interface{}{},
	})

	e.Apply(origReq, upstreamReq, body, false, "seed", "acct-learn")

	// After processing a real CC client, the fingerprint should be learned
	fp := e.fingerprints.Get("acct-learn")
	if fp.UserAgent != "claude-cli/2.3.0 (external, cli)" {
		t.Errorf("expected learned UA from CC client, got %q", fp.UserAgent)
	}
	if fp.StainlessOS != "Darwin" {
		t.Errorf("expected learned OS from CC client, got %q", fp.StainlessOS)
	}
}
