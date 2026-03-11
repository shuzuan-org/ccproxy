package proxy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// IsSignatureError checks if a 400 response body indicates a thinking block signature error.
func IsSignatureError(body []byte) bool {
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	msg := strings.ToLower(parsed.Error.Message)
	if msg == "" {
		return false
	}

	if strings.Contains(msg, "signature") {
		return true
	}
	if strings.Contains(msg, "expected") && (strings.Contains(msg, "thinking") || strings.Contains(msg, "redacted_thinking")) {
		return true
	}
	if strings.Contains(msg, "cannot be modified") && (strings.Contains(msg, "thinking") || strings.Contains(msg, "redacted_thinking")) {
		return true
	}
	if strings.Contains(msg, "non-empty content") || strings.Contains(msg, "empty content") {
		return true
	}
	return false
}

// IsToolRelatedError checks if the error message mentions tool blocks.
func IsToolRelatedError(body []byte) bool {
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}
	msg := strings.ToLower(parsed.Error.Message)
	return strings.Contains(msg, "tool_use") || strings.Contains(msg, "tool_result")
}

// FilterThinkingBlocks converts thinking/redacted_thinking content blocks to text.
// thinking → text (preserving content), redacted_thinking → removed.
// Also removes the top-level "thinking" field.
func FilterThinkingBlocks(body []byte) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}

	// Remove top-level "thinking" configuration.
	delete(parsed, "thinking")

	// Process messages.
	messages, ok := parsed["messages"].([]any)
	if !ok {
		result, _ := json.Marshal(parsed)
		return result
	}

	for i, msg := range messages {
		msgMap, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		content, ok := msgMap["content"].([]any)
		if !ok {
			continue
		}

		filtered := filterThinkingFromContent(content)
		msgMap["content"] = filtered
		messages[i] = msgMap
	}

	parsed["messages"] = messages
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

// FilterSignatureSensitiveBlocks does FilterThinkingBlocks + converts tool_use/tool_result to text.
func FilterSignatureSensitiveBlocks(body []byte) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}

	delete(parsed, "thinking")

	messages, ok := parsed["messages"].([]any)
	if !ok {
		result, _ := json.Marshal(parsed)
		return result
	}

	for i, msg := range messages {
		msgMap, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		content, ok := msgMap["content"].([]any)
		if !ok {
			continue
		}

		filtered := filterThinkingFromContent(content)
		filtered = filterToolsFromContent(filtered)
		msgMap["content"] = filtered
		messages[i] = msgMap
	}

	parsed["messages"] = messages
	result, err := json.Marshal(parsed)
	if err != nil {
		return body
	}
	return result
}

// filterThinkingFromContent processes content blocks:
// thinking → text, redacted_thinking → removed, empty → placeholder.
func filterThinkingFromContent(content []any) []any {
	var result []any
	for _, block := range content {
		blockMap, ok := block.(map[string]any)
		if !ok {
			result = append(result, block)
			continue
		}

		blockType, _ := blockMap["type"].(string)
		switch blockType {
		case "thinking":
			text, _ := blockMap["thinking"].(string)
			if text == "" {
				text, _ = blockMap["text"].(string)
			}
			result = append(result, map[string]any{
				"type": "text",
				"text": text,
			})
		case "redacted_thinking":
			// Remove entirely.
		default:
			result = append(result, block)
		}
	}

	if len(result) == 0 {
		result = append(result, map[string]any{
			"type": "text",
			"text": "(content removed)",
		})
	}
	return result
}

// filterToolsFromContent converts tool_use and tool_result blocks to text.
func filterToolsFromContent(content []any) []any {
	var result []any
	for _, block := range content {
		blockMap, ok := block.(map[string]any)
		if !ok {
			result = append(result, block)
			continue
		}

		blockType, _ := blockMap["type"].(string)
		switch blockType {
		case "tool_use":
			name, _ := blockMap["name"].(string)
			id, _ := blockMap["id"].(string)
			inputJSON, _ := json.Marshal(blockMap["input"])
			result = append(result, map[string]any{
				"type": "text",
				"text": fmt.Sprintf("(tool_use) name=%s id=%s input=%s", name, id, string(inputJSON)),
			})
		case "tool_result":
			toolUseID, _ := blockMap["tool_use_id"].(string)
			contentStr := ""
			switch c := blockMap["content"].(type) {
			case string:
				contentStr = c
			default:
				cJSON, _ := json.Marshal(c)
				contentStr = string(cJSON)
			}
			result = append(result, map[string]any{
				"type": "text",
				"text": fmt.Sprintf("(tool_result) tool_use_id=%s content=%s", toolUseID, contentStr),
			})
		default:
			result = append(result, block)
		}
	}
	return result
}
