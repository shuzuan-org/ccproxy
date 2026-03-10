package disguise

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

var (
	claudeCLIRegex = regexp.MustCompile(`^claude-cli/\d+\.\d+\.\d+`)
	metadataRegex  = regexp.MustCompile(`^user_[a-fA-F0-9]{64}_account__session_[\w-]+$`)
)

// Claude Code system prompt prefixes for similarity matching
var claudeCodePromptPrefixes = []string{
	"You are Claude Code, Anthropic's official CLI for Claude",
	"You are a Claude agent, built on Anthropic's Claude Agent SDK",
	"You are a file search specialist for Claude Code",
	"You are a helpful AI assistant tasked with summarizing conversations",
	"You are an agent for Claude Code",
	"You are Claude, made by Anthropic",
}

// IsClaudeCodeClient checks if the request appears to be from a real Claude Code client.
// Uses multi-signal validation: requires at least 3 of 5 signals to match.
func IsClaudeCodeClient(headers http.Header, body []byte) bool {
	score := 0

	// Signal 1: User-Agent matches claude-cli pattern
	if claudeCLIRegex.MatchString(headers.Get("User-Agent")) {
		score++
	}

	// Signal 2: X-App header is "cli"
	if headers.Get("X-App") == "cli" {
		score++
	}

	// Signal 3: anthropic-beta contains claude-code marker
	if strings.Contains(headers.Get("Anthropic-Beta"), BetaClaudeCode) {
		score++
	}

	// Signal 4: metadata.user_id matches expected format
	if checkMetadataUserID(body) {
		score++
	}

	// Signal 5: System prompt similarity
	if checkSystemPromptSimilarity(body) {
		score++
	}

	return score >= 3
}

func checkMetadataUserID(body []byte) bool {
	var req struct {
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	return metadataRegex.MatchString(req.Metadata.UserID)
}

func checkSystemPromptSimilarity(body []byte) bool {
	var req struct {
		System interface{} `json:"system"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}

	systemText := extractSystemText(req.System)
	if systemText == "" {
		return false
	}

	for _, prefix := range claudeCodePromptPrefixes {
		if strings.HasPrefix(systemText, prefix) {
			return true
		}
		if DiceCoefficient(systemText[:min(len(systemText), 200)], prefix) >= 0.5 {
			return true
		}
	}
	return false
}

func extractSystemText(system interface{}) string {
	switch v := system.(type) {
	case string:
		return v
	case []interface{}:
		// Array format: [{"type":"text","text":"..."}]
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok {
				if t, ok := m["text"].(string); ok {
					return t
				}
			}
		}
	}
	return ""
}

// DiceCoefficient calculates the Sorensen-Dice coefficient between two strings.
// Returns a value between 0.0 (no similarity) and 1.0 (identical).
func DiceCoefficient(a, b string) float64 {
	if len(a) < 2 || len(b) < 2 {
		if a == b {
			return 1.0
		}
		return 0.0
	}

	aBigrams := make(map[string]int)
	for i := 0; i < len(a)-1; i++ {
		bigram := a[i : i+2]
		aBigrams[bigram]++
	}

	bBigrams := make(map[string]int)
	for i := 0; i < len(b)-1; i++ {
		bigram := b[i : i+2]
		bBigrams[bigram]++
	}

	intersection := 0
	for bigram, countA := range aBigrams {
		if countB, ok := bBigrams[bigram]; ok {
			intersection += min(countA, countB)
		}
	}

	return 2.0 * float64(intersection) / float64(len(a)-1+len(b)-1)
}
