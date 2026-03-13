package disguise

import (
	"encoding/json"
	"log/slog"
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
// Uses layered validation:
//   - Gate: User-Agent MUST match claude-cli pattern (mandatory).
//   - Non-messages path: UA match alone is sufficient.
//   - Haiku probe: max_tokens=1 + haiku + !stream passes immediately.
//   - Messages path: requires >=2 of 4 additional signals.
func IsClaudeCodeClient(headers http.Header, body []byte, path string) bool {
	ua := headers.Get("User-Agent")
	// Gate: UA MUST match (mandatory)
	if !claudeCLIRegex.MatchString(ua) {
		slog.Debug("disguise/detect: UA gate failed, not CC client",
			"user_agent", ua,
		)
		return false
	}

	// Non-messages path: UA match is sufficient
	if !strings.HasSuffix(path, "/v1/messages") {
		slog.Debug("disguise/detect: non-messages path, UA match sufficient",
			"path", path,
			"user_agent", ua,
		)
		return true
	}

	// Haiku probe: max_tokens=1 + haiku + !stream → pass
	if isHaikuProbe(body) {
		slog.Debug("disguise/detect: haiku probe detected, pass-through")
		return true
	}

	// Messages path: strict multi-signal validation (need >=2 of 4)
	xApp := headers.Get("X-App") == "cli"
	hasBeta := strings.Contains(headers.Get("Anthropic-Beta"), BetaClaudeCode)
	hasUserID := checkMetadataUserID(body)
	hasSystemPrompt := checkSystemPromptSimilarity(body)

	score := 0
	if xApp {
		score++
	}
	if hasBeta {
		score++
	}
	if hasUserID {
		score++
	}
	if hasSystemPrompt {
		score++
	}

	isCC := score >= 2
	slog.Debug("disguise/detect: multi-signal validation",
		"is_cc", isCC,
		"score", score,
		"x_app_cli", xApp,
		"has_cc_beta", hasBeta,
		"has_user_id", hasUserID,
		"has_system_prompt", hasSystemPrompt,
		"user_agent", ua,
	)
	return isCC
}

// isHaikuProbe detects lightweight Haiku probe requests (max_tokens=1, haiku model, non-streaming).
func isHaikuProbe(body []byte) bool {
	var req struct {
		Model     string `json:"model"`
		MaxTokens int    `json:"max_tokens"`
		Stream    bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	return req.MaxTokens == 1 && IsHaikuModel(req.Model) && !req.Stream
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
// Uses pre-allocated map capacity to reduce allocations.
func DiceCoefficient(a, b string) float64 {
	if len(a) < 2 || len(b) < 2 {
		if a == b {
			return 1.0
		}
		return 0.0
	}

	aBigrams := make(map[string]int, len(a)-1)
	for i := 0; i < len(a)-1; i++ {
		bigram := a[i : i+2]
		aBigrams[bigram]++
	}

	bBigrams := make(map[string]int, len(b)-1)
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
