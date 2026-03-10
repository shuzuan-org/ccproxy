package session

import (
	"testing"
)

func TestExtractSessionID(t *testing.T) {
	tests := []struct {
		name     string
		userID   string
		expected string
	}{
		{
			name:     "valid user_id with session UUID",
			userID:   "user_e7073098c4527edc7ca78d99ea8929817983cd0b981ba5c34c88bdb5366c0806_account__session_0ac9289a-471e-4b6a-bdff-ffc2f53cb0e3",
			expected: "0ac9289a-471e-4b6a-bdff-ffc2f53cb0e3",
		},
		{
			name:     "no session part",
			userID:   "user_e7073098c4527edc7ca78d99ea8929817983cd0b981ba5c34c88bdb5366c0806_account",
			expected: "",
		},
		{
			name:     "empty string",
			userID:   "",
			expected: "",
		},
		{
			name:     "malformed UUID (wrong character set)",
			userID:   "user_abc_account__session_XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractSessionID(tt.userID)
			if got != tt.expected {
				t.Errorf("ExtractSessionID(%q) = %q, want %q", tt.userID, got, tt.expected)
			}
		})
	}
}

func TestComposeSessionKey(t *testing.T) {
	tests := []struct {
		name       string
		apiKeyName string
		sessionID  string
		expected   string
	}{
		{
			name:       "with session ID",
			apiKeyName: "dev-team",
			sessionID:  "0ac9289a-471e-4b6a-bdff-ffc2f53cb0e3",
			expected:   "dev-team:0ac9289a-471e-4b6a-bdff-ffc2f53cb0e3",
		},
		{
			name:       "without session ID",
			apiKeyName: "dev-team",
			sessionID:  "",
			expected:   "dev-team",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComposeSessionKey(tt.apiKeyName, tt.sessionID)
			if got != tt.expected {
				t.Errorf("ComposeSessionKey(%q, %q) = %q, want %q", tt.apiKeyName, tt.sessionID, got, tt.expected)
			}
		})
	}
}
