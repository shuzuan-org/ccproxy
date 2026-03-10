package session

import (
	"regexp"
)

var sessionRe = regexp.MustCompile(`session_([a-f0-9-]{36})$`)

// ExtractSessionID extracts the UUID session ID from a metadata.user_id string.
// Format: user_{64hex}_account__session_{uuid}
// Returns empty string if format doesn't match.
func ExtractSessionID(userID string) string {
	matches := sessionRe.FindStringSubmatch(userID)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// ComposeSessionKey creates a session key combining API key name and session ID.
// If sessionID is empty, returns just the apiKeyName.
func ComposeSessionKey(apiKeyName, sessionID string) string {
	if sessionID == "" {
		return apiKeyName
	}
	return apiKeyName + ":" + sessionID
}
