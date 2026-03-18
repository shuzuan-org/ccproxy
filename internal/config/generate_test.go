package config

import (
	"strings"
	"testing"
)

func TestGenerateAdminPassword(t *testing.T) {
	t.Parallel()

	pw := GenerateAdminPassword()
	if len(pw) != adminPasswordLength {
		t.Errorf("password length = %d, want %d", len(pw), adminPasswordLength)
	}

	// Every character must be in the allowed charset
	for i, c := range pw {
		if !strings.ContainsRune(passwordCharset, c) {
			t.Errorf("password[%d] = %q, not in charset", i, string(c))
		}
	}

	// Two consecutive calls should produce different values
	pw2 := GenerateAdminPassword()
	if pw == pw2 {
		t.Error("two calls returned the same password")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	t.Parallel()

	key := GenerateAPIKey()
	if !strings.HasPrefix(key, apiKeyPrefix) {
		t.Errorf("api key %q missing prefix %q", key, apiKeyPrefix)
	}

	hexPart := strings.TrimPrefix(key, apiKeyPrefix)
	if len(hexPart) != apiKeyHexLength {
		t.Errorf("api key hex part length = %d, want %d", len(hexPart), apiKeyHexLength)
	}

	// Hex chars only
	for i, c := range hexPart {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("api key hex[%d] = %q, not a hex char", i, string(c))
		}
	}

	// Two consecutive calls should produce different values
	key2 := GenerateAPIKey()
	if key == key2 {
		t.Error("two calls returned the same api key")
	}
}

func TestInsertAdminPassword_ReplaceEmpty(t *testing.T) {
	t.Parallel()

	content := `[server]
host = "0.0.0.0"
admin_password = ""
port = 3000
`
	result := insertAdminPassword(content, "newpass123")
	if !strings.Contains(result, `admin_password = "newpass123"`) {
		t.Errorf("expected replaced admin_password, got:\n%s", result)
	}
	// Original empty line should be gone
	if strings.Contains(result, `admin_password = ""`) {
		t.Error("old empty admin_password still present")
	}
}

func TestInsertAdminPassword_AppendAfterServer(t *testing.T) {
	t.Parallel()

	content := `[server]
host = "0.0.0.0"
port = 3000
`
	result := insertAdminPassword(content, "newpass123")
	if !strings.Contains(result, `admin_password = "newpass123"`) {
		t.Errorf("expected appended admin_password, got:\n%s", result)
	}
	// Should appear after [server]
	serverIdx := strings.Index(result, "[server]")
	passIdx := strings.Index(result, "admin_password")
	if passIdx < serverIdx {
		t.Error("admin_password should appear after [server]")
	}
}

func TestInsertAdminPassword_NoServerSection(t *testing.T) {
	t.Parallel()

	content := `[[accounts]]
name = "test"
`
	result := insertAdminPassword(content, "newpass123")
	if !strings.Contains(result, "[server]") {
		t.Error("expected [server] section to be added")
	}
	if !strings.Contains(result, `admin_password = "newpass123"`) {
		t.Errorf("expected admin_password, got:\n%s", result)
	}
}

func TestAppendAPIKey(t *testing.T) {
	t.Parallel()

	content := `[server]
admin_password = "test"
`
	k := APIKeyConfig{Key: "sk-abc123def456", Name: "default", Enabled: true}
	result := appendAPIKey(content, k)
	if !strings.Contains(result, "[[api_keys]]") {
		t.Error("expected [[api_keys]] block")
	}
	if !strings.Contains(result, `key = "sk-abc123def456"`) {
		t.Error("expected key value")
	}
	if !strings.Contains(result, `name = "default"`) {
		t.Error("expected name value")
	}
}
