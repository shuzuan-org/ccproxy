package proxy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIsSignatureError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "signature keyword",
			body: `{"error":{"type":"invalid_request_error","message":"Invalid signature for thinking block"}}`,
			want: true,
		},
		{
			name: "expected thinking",
			body: `{"error":{"type":"invalid_request_error","message":"expected thinking block in messages"}}`,
			want: true,
		},
		{
			name: "expected redacted_thinking",
			body: `{"error":{"type":"invalid_request_error","message":"expected redacted_thinking block"}}`,
			want: true,
		},
		{
			name: "cannot be modified thinking",
			body: `{"error":{"type":"invalid_request_error","message":"thinking blocks cannot be modified"}}`,
			want: true,
		},
		{
			name: "non-empty content",
			body: `{"error":{"type":"invalid_request_error","message":"non-empty content required"}}`,
			want: true,
		},
		{
			name: "empty content",
			body: `{"error":{"type":"invalid_request_error","message":"empty content not allowed"}}`,
			want: true,
		},
		{
			name: "unrelated error",
			body: `{"error":{"type":"invalid_request_error","message":"model not found"}}`,
			want: false,
		},
		{
			name: "invalid json",
			body: `not json`,
			want: false,
		},
		{
			name: "empty message",
			body: `{"error":{"type":"invalid_request_error","message":""}}`,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := IsSignatureError([]byte(tc.body))
			if got != tc.want {
				t.Errorf("IsSignatureError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsToolRelatedError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "tool_use mentioned",
			body: `{"error":{"message":"invalid tool_use block signature"}}`,
			want: true,
		},
		{
			name: "tool_result mentioned",
			body: `{"error":{"message":"tool_result block error"}}`,
			want: true,
		},
		{
			name: "no tool mention",
			body: `{"error":{"message":"thinking block error"}}`,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := IsToolRelatedError([]byte(tc.body))
			if got != tc.want {
				t.Errorf("IsToolRelatedError() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFilterThinkingBlocks(t *testing.T) {
	t.Parallel()

	body := `{
		"model": "claude-sonnet-4-5",
		"thinking": {"type": "enabled", "budget_tokens": 1024},
		"messages": [
			{
				"role": "user",
				"content": [{"type": "text", "text": "hello"}]
			},
			{
				"role": "assistant",
				"content": [
					{"type": "thinking", "thinking": "let me think..."},
					{"type": "redacted_thinking", "data": "abc"},
					{"type": "text", "text": "response"}
				]
			}
		]
	}`

	result := FilterThinkingBlocks([]byte(body))

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	// "thinking" top-level field should be removed.
	if _, ok := parsed["thinking"]; ok {
		t.Error("top-level 'thinking' field should be removed")
	}

	// Check assistant message content.
	messages := parsed["messages"].([]any)
	assistantMsg := messages[1].(map[string]any)
	content := assistantMsg["content"].([]any)

	// Should have 2 blocks: thinking→text, text (redacted removed).
	if len(content) != 2 {
		t.Fatalf("expected 2 content blocks, got %d", len(content))
	}

	// First block: thinking converted to text.
	block0 := content[0].(map[string]any)
	if block0["type"] != "text" {
		t.Errorf("block 0 type = %v, want text", block0["type"])
	}
	if block0["text"] != "let me think..." {
		t.Errorf("block 0 text = %v, want 'let me think...'", block0["text"])
	}

	// Second block: original text.
	block1 := content[1].(map[string]any)
	if block1["type"] != "text" {
		t.Errorf("block 1 type = %v, want text", block1["type"])
	}
	if block1["text"] != "response" {
		t.Errorf("block 1 text = %v, want 'response'", block1["text"])
	}
}

func TestFilterThinkingBlocks_EmptyContent(t *testing.T) {
	t.Parallel()

	// All content blocks are redacted — should get placeholder.
	body := `{
		"messages": [{
			"role": "assistant",
			"content": [
				{"type": "redacted_thinking", "data": "abc"}
			]
		}]
	}`

	result := FilterThinkingBlocks([]byte(body))

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	messages := parsed["messages"].([]any)
	msg := messages[0].(map[string]any)
	content := msg["content"].([]any)

	if len(content) != 1 {
		t.Fatalf("expected 1 placeholder block, got %d", len(content))
	}
	block := content[0].(map[string]any)
	if block["text"] != "(content removed)" {
		t.Errorf("placeholder text = %v, want '(content removed)'", block["text"])
	}
}

func TestFilterThinkingBlocks_NoThinking(t *testing.T) {
	t.Parallel()

	body := `{
		"model": "claude-sonnet-4-5",
		"messages": [{
			"role": "user",
			"content": [{"type": "text", "text": "hello"}]
		}]
	}`

	result := FilterThinkingBlocks([]byte(body))

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	messages := parsed["messages"].([]any)
	msg := messages[0].(map[string]any)
	content := msg["content"].([]any)

	if len(content) != 1 {
		t.Fatalf("expected 1 block, got %d", len(content))
	}
	block := content[0].(map[string]any)
	if block["text"] != "hello" {
		t.Errorf("text = %v, want 'hello'", block["text"])
	}
}

func TestFilterThinkingBlocks_RemovesClearThinkingStrategy(t *testing.T) {
	t.Parallel()

	body := `{
		"thinking": {"type": "enabled", "budget_tokens": 1024},
		"context_management": {
			"edits": [
				{"type": "clear_thinking_20251015"},
				{"type": "summarize_20250101"}
			]
		},
		"messages": [{
			"role": "assistant",
			"content": [
				{"type": "thinking", "thinking": "hmm"},
				{"type": "text", "text": "ok"}
			]
		}]
	}`

	result := FilterThinkingBlocks([]byte(body))

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	// thinking top-level should be removed
	if _, ok := parsed["thinking"]; ok {
		t.Error("top-level 'thinking' should be removed")
	}

	// context_management.edits should not have clear_thinking
	cm, ok := parsed["context_management"].(map[string]any)
	if !ok {
		t.Fatal("expected context_management to exist")
	}
	edits, ok := cm["edits"].([]any)
	if !ok {
		t.Fatal("expected edits to exist")
	}

	for _, edit := range edits {
		editMap := edit.(map[string]any)
		editType, _ := editMap["type"].(string)
		if strings.HasPrefix(editType, "clear_thinking") {
			t.Errorf("clear_thinking strategy should have been removed, found: %q", editType)
		}
	}

	// summarize should still be present
	if len(edits) != 1 {
		t.Errorf("expected 1 remaining edit, got %d", len(edits))
	}
}

func TestFilterThinkingBlocks_RemovesEditsFieldWhenEmpty(t *testing.T) {
	t.Parallel()

	body := `{
		"thinking": {"type": "enabled"},
		"context_management": {
			"edits": [
				{"type": "clear_thinking_20251015"}
			]
		},
		"messages": [{
			"role": "user",
			"content": [{"type": "text", "text": "hello"}]
		}]
	}`

	result := FilterThinkingBlocks([]byte(body))

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	cm, ok := parsed["context_management"].(map[string]any)
	if !ok {
		t.Fatal("expected context_management to exist")
	}

	if _, hasEdits := cm["edits"]; hasEdits {
		t.Error("edits field should be deleted when all entries are filtered")
	}
}

func TestFilterThinkingBlocks_NoContextManagement(t *testing.T) {
	t.Parallel()

	// Should not panic or error when no context_management field exists
	body := `{
		"thinking": {"type": "enabled"},
		"messages": [{
			"role": "user",
			"content": [{"type": "text", "text": "hello"}]
		}]
	}`

	result := FilterThinkingBlocks([]byte(body))

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	if _, ok := parsed["thinking"]; ok {
		t.Error("top-level 'thinking' should be removed")
	}
}

func TestFilterSignatureSensitiveBlocks(t *testing.T) {
	t.Parallel()

	body := `{
		"thinking": {"type": "enabled"},
		"messages": [{
			"role": "assistant",
			"content": [
				{"type": "thinking", "thinking": "hmm"},
				{"type": "tool_use", "name": "search", "id": "tu_1", "input": {"query": "test"}},
				{"type": "text", "text": "result"}
			]
		},{
			"role": "user",
			"content": [
				{"type": "tool_result", "tool_use_id": "tu_1", "content": "found it"}
			]
		}]
	}`

	result := FilterSignatureSensitiveBlocks([]byte(body))
	resultStr := string(result)

	var parsed map[string]any
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}

	// thinking should be removed.
	if _, ok := parsed["thinking"]; ok {
		t.Error("top-level 'thinking' should be removed")
	}

	// Check tool_use was converted.
	if !strings.Contains(resultStr, "(tool_use) name=search id=tu_1") {
		t.Errorf("tool_use not converted to text: %s", resultStr)
	}

	// Check tool_result was converted.
	if !strings.Contains(resultStr, "(tool_result) tool_use_id=tu_1 content=found it") {
		t.Errorf("tool_result not converted to text: %s", resultStr)
	}

	// No more tool_use/tool_result types.
	if strings.Contains(resultStr, `"type":"tool_use"`) {
		t.Error("tool_use type should have been replaced")
	}
	if strings.Contains(resultStr, `"type":"tool_result"`) {
		t.Error("tool_result type should have been replaced")
	}
}
