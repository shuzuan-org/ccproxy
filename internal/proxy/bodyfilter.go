package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// HasThinkingBlocks reports whether body contains any thinking or redacted_thinking
// content blocks. Uses a byte scan on compact JSON — avoids full parse overhead.
// False positives are safe: FilterThinkingBlocks is a no-op when no blocks exist.
func HasThinkingBlocks(body []byte) bool {
	return bytes.Contains(body, []byte(`"type":"thinking"`)) ||
		bytes.Contains(body, []byte(`"type":"redacted_thinking"`))
}

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
	return filterBlocks(body, func(content []any) ([]any, int, int) {
		return filterThinkingFromContent(content)
	})
}

// FilterSignatureSensitiveBlocks does FilterThinkingBlocks + converts tool_use/tool_result to text.
func FilterSignatureSensitiveBlocks(body []byte) []byte {
	return filterBlocks(body, func(content []any) ([]any, int, int) {
		filtered, conv, rem := filterThinkingFromContent(content)
		return filterToolsFromContent(filtered), conv, rem
	})
}

// filterBlocks is the shared implementation for FilterThinkingBlocks and
// FilterSignatureSensitiveBlocks. It removes top-level "thinking" and applies
// the given content filter to each message's content array.
func filterBlocks(body []byte, contentFilter func([]any) ([]any, int, int)) []byte {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}

	delete(parsed, "thinking")

	// Remove thinking-dependent context management strategies (e.g. clear_thinking)
	// since thinking blocks are being filtered out.
	removeThinkingDependentContextStrategies(parsed)

	messages, ok := parsed["messages"].([]any)
	if !ok {
		result, _ := json.Marshal(parsed)
		return result
	}

	totalConverted, totalRemoved := 0, 0
	for i, msg := range messages {
		msgMap, ok := msg.(map[string]any)
		if !ok {
			continue
		}
		content, ok := msgMap["content"].([]any)
		if !ok {
			continue
		}

		filtered, conv, rem := contentFilter(content)
		totalConverted += conv
		totalRemoved += rem
		filtered = stripEmptyTextBlocks(filtered)
		if len(filtered) == 0 {
			filtered = []any{map[string]any{
				"type": "text",
				"text": "(content removed)",
			}}
		}
		msgMap["content"] = filtered
		messages[i] = msgMap
	}

	if totalConverted > 0 || totalRemoved > 0 {
		slog.Debug("bodyfilter: thinking blocks filtered",
			"thinking_to_text", totalConverted,
			"redacted_removed", totalRemoved,
		)
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
// Returns (filtered content, converted count, removed count).
func filterThinkingFromContent(content []any) ([]any, int, int) {
	var result []any
	converted, removed := 0, 0
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
			if text == "" {
				// Skip: don't create empty text blocks (Anthropic rejects them)
				removed++
				continue
			}
			result = append(result, map[string]any{
				"type": "text",
				"text": text,
			})
			converted++
		case "redacted_thinking":
			removed++
		default:
			result = append(result, block)
		}
	}

	return result, converted, removed
}

// stripEmptyTextBlocks removes text blocks with empty content.
// Anthropic rejects empty text blocks with a 400 error.
func stripEmptyTextBlocks(content []any) []any {
	result := make([]any, 0, len(content))
	for _, block := range content {
		blockMap, ok := block.(map[string]any)
		if !ok {
			result = append(result, block)
			continue
		}
		if blockMap["type"] == "text" {
			if text, _ := blockMap["text"].(string); text == "" {
				continue
			}
		}
		result = append(result, block)
	}
	return result
}

// removeThinkingDependentContextStrategies removes context_management edits
// that depend on thinking blocks (e.g. "clear_thinking_20251015"). Called when
// thinking blocks are being filtered out, to prevent API errors from referencing
// strategies that no longer apply. Mutates parsed in-place.
func removeThinkingDependentContextStrategies(parsed map[string]any) {
	cm, ok := parsed["context_management"].(map[string]any)
	if !ok {
		return
	}
	edits, ok := cm["edits"].([]any)
	if !ok {
		return
	}

	filtered := make([]any, 0, len(edits))
	for _, edit := range edits {
		editMap, ok := edit.(map[string]any)
		if !ok {
			filtered = append(filtered, edit)
			continue
		}
		editType, _ := editMap["type"].(string)
		if strings.HasPrefix(editType, "clear_thinking") {
			continue
		}
		filtered = append(filtered, edit)
	}

	if len(filtered) == 0 {
		delete(cm, "edits")
	} else {
		cm["edits"] = filtered
	}
}

// filterToolsFromContent converts tool_use and tool_result blocks to text.
func filterToolsFromContent(content []any) []any {
	var result []any
	converted := 0
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
			converted++
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
			converted++
		default:
			result = append(result, block)
		}
	}
	if converted > 0 {
		slog.Debug("bodyfilter: tool blocks filtered",
			"tools_to_text", converted,
		)
	}
	return result
}
