package disguise

// CleanThinkingCacheControl removes cache_control from thinking blocks
// in system[] and messages[].content[]. Anthropic API rejects thinking
// blocks with cache_control. Returns true if any field was removed.
func CleanThinkingCacheControl(parsed map[string]interface{}) bool {
	modified := false

	// Clean system array
	if system, ok := parsed["system"].([]interface{}); ok {
		for _, item := range system {
			if cleanThinkingBlock(item) {
				modified = true
			}
		}
	}

	// Clean messages array
	if messages, ok := parsed["messages"].([]interface{}); ok {
		for _, msg := range messages {
			m, ok := msg.(map[string]interface{})
			if !ok {
				continue
			}
			content, ok := m["content"].([]interface{})
			if !ok {
				continue
			}
			for _, block := range content {
				if cleanThinkingBlock(block) {
					modified = true
				}
			}
		}
	}

	return modified
}

// cleanThinkingBlock removes cache_control from a single block if its type is "thinking".
func cleanThinkingBlock(block interface{}) bool {
	m, ok := block.(map[string]interface{})
	if !ok {
		return false
	}
	blockType, _ := m["type"].(string)
	if blockType != "thinking" {
		return false
	}
	if _, has := m["cache_control"]; has {
		delete(m, "cache_control")
		return true
	}
	return false
}
