package disguise

import (
	"encoding/json"
	"testing"
)

func TestCleanThinkingCacheControl_ThinkingBlockInSystem(t *testing.T) {
	t.Parallel()
	parsed := map[string]interface{}{
		"system": []interface{}{
			map[string]interface{}{
				"type":          "thinking",
				"text":          "some thought",
				"cache_control": map[string]interface{}{"type": "ephemeral"},
			},
		},
	}

	modified := CleanThinkingCacheControl(parsed)
	if !modified {
		t.Error("expected modified=true when thinking block has cache_control")
	}

	block := parsed["system"].([]interface{})[0].(map[string]interface{})
	if _, has := block["cache_control"]; has {
		t.Error("expected cache_control to be removed from thinking block")
	}
	// type and text should remain
	if block["type"] != "thinking" {
		t.Error("expected type to remain 'thinking'")
	}
	if block["text"] != "some thought" {
		t.Error("expected text to remain unchanged")
	}
}

func TestCleanThinkingCacheControl_TextBlockPreserved(t *testing.T) {
	t.Parallel()
	parsed := map[string]interface{}{
		"system": []interface{}{
			map[string]interface{}{
				"type":          "text",
				"text":          "hello",
				"cache_control": map[string]interface{}{"type": "ephemeral"},
			},
		},
	}

	modified := CleanThinkingCacheControl(parsed)
	if modified {
		t.Error("expected modified=false when only text blocks have cache_control")
	}

	block := parsed["system"].([]interface{})[0].(map[string]interface{})
	if _, has := block["cache_control"]; !has {
		t.Error("expected cache_control to be preserved on text block")
	}
}

func TestCleanThinkingCacheControl_NoThinkingBlocks(t *testing.T) {
	t.Parallel()
	parsed := map[string]interface{}{
		"system": []interface{}{
			map[string]interface{}{
				"type": "text",
				"text": "hello",
			},
		},
		"messages": []interface{}{
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{"type": "text", "text": "hi"},
				},
			},
		},
	}

	modified := CleanThinkingCacheControl(parsed)
	if modified {
		t.Error("expected modified=false when no thinking blocks exist")
	}
}

func TestCleanThinkingCacheControl_ThinkingInMessages(t *testing.T) {
	t.Parallel()
	parsed := map[string]interface{}{
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
	}

	modified := CleanThinkingCacheControl(parsed)
	if !modified {
		t.Error("expected modified=true for thinking block in messages")
	}

	content := parsed["messages"].([]interface{})[0].(map[string]interface{})["content"].([]interface{})

	// Thinking block should have cache_control removed
	thinkBlock := content[0].(map[string]interface{})
	if _, has := thinkBlock["cache_control"]; has {
		t.Error("expected cache_control removed from thinking block in messages")
	}

	// Text block should retain cache_control
	textBlock := content[1].(map[string]interface{})
	if _, has := textBlock["cache_control"]; !has {
		t.Error("expected cache_control preserved on text block in messages")
	}
}

func TestCleanThinkingCacheControl_RoundTrip(t *testing.T) {
	t.Parallel()
	// Verify the function works correctly when integrated with JSON marshal/unmarshal.
	input := `{
		"system": [
			{"type": "thinking", "text": "thought", "cache_control": {"type": "ephemeral"}},
			{"type": "text", "text": "hello", "cache_control": {"type": "ephemeral"}}
		],
		"messages": [
			{"role": "assistant", "content": [
				{"type": "thinking", "thinking": "deep", "cache_control": {"type": "ephemeral"}}
			]}
		]
	}`

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(input), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	modified := CleanThinkingCacheControl(parsed)
	if !modified {
		t.Error("expected modified=true")
	}

	output, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Re-parse and verify
	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}

	system := result["system"].([]interface{})
	thinkBlock := system[0].(map[string]interface{})
	if _, has := thinkBlock["cache_control"]; has {
		t.Error("thinking block should not have cache_control after round-trip")
	}
	textBlock := system[1].(map[string]interface{})
	if _, has := textBlock["cache_control"]; !has {
		t.Error("text block should still have cache_control after round-trip")
	}
}
