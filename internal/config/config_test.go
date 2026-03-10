package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemp writes content to a temp file and returns the path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "ccproxy-*.toml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

// validConfig is the canonical "everything present" fixture.
const validConfigTOML = `
[server]
host = "0.0.0.0"
port = 8080
log_level = "debug"
admin_password = "secret"

[[api_keys]]
key = "sk-test-001"
name = "team-a"
enabled = true

[[instances]]
name = "alice-oauth"
auth_mode = "oauth"
oauth_provider = "anthropic"
priority = 2
weight = 50
max_concurrency = 3
base_url = "https://api.anthropic.com"
request_timeout = 120
tls_fingerprint = true

[[instances]]
name = "bob-bearer"
auth_mode = "bearer"
api_key = "sk-ant-real-key"
priority = 1
weight = 100
max_concurrency = 10
base_url = "https://api.anthropic.com"
request_timeout = 60
tls_fingerprint = false

[[oauth_providers]]
name = "anthropic"
client_id = "my-client-id"
auth_url = "https://claude.ai/oauth/authorize"
token_url = "https://console.anthropic.com/v1/oauth/token"
redirect_uri = "https://platform.claude.com/oauth/code/callback"
scopes = ["org:create_api_key", "user:profile"]

[observability]
retention_days = 30
`

func TestLoadConfig_Valid(t *testing.T) {
	path := writeTemp(t, validConfigTOML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Server
	if cfg.Server.Host != "0.0.0.0" {
		t.Errorf("host = %q, want 0.0.0.0", cfg.Server.Host)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("log_level = %q, want debug", cfg.Server.LogLevel)
	}
	if cfg.Server.AdminPassword != "secret" {
		t.Errorf("admin_password = %q, want secret", cfg.Server.AdminPassword)
	}

	// API keys
	if len(cfg.APIKeys) != 1 {
		t.Fatalf("api_keys len = %d, want 1", len(cfg.APIKeys))
	}
	if cfg.APIKeys[0].Key != "sk-test-001" {
		t.Errorf("api_key.key = %q, want sk-test-001", cfg.APIKeys[0].Key)
	}
	if !cfg.APIKeys[0].Enabled {
		t.Error("api_key.enabled should be true")
	}

	// Instances
	if len(cfg.Instances) != 2 {
		t.Fatalf("instances len = %d, want 2", len(cfg.Instances))
	}
	alice := cfg.Instances[0]
	if alice.Name != "alice-oauth" {
		t.Errorf("instance[0].name = %q, want alice-oauth", alice.Name)
	}
	if !alice.IsOAuth() {
		t.Error("alice should be oauth")
	}
	if alice.OAuthProvider != "anthropic" {
		t.Errorf("alice.oauth_provider = %q, want anthropic", alice.OAuthProvider)
	}
	if alice.Priority != 2 {
		t.Errorf("alice.priority = %d, want 2", alice.Priority)
	}
	if alice.Weight != 50 {
		t.Errorf("alice.weight = %d, want 50", alice.Weight)
	}
	if alice.MaxConcurrency != 3 {
		t.Errorf("alice.max_concurrency = %d, want 3", alice.MaxConcurrency)
	}
	if alice.RequestTimeout != 120 {
		t.Errorf("alice.request_timeout = %d, want 120", alice.RequestTimeout)
	}
	if !alice.TLSFingerprint {
		t.Error("alice.tls_fingerprint should be true")
	}
	if !alice.IsEnabled() {
		t.Error("alice should be enabled by default")
	}

	bob := cfg.Instances[1]
	if bob.AuthMode != "bearer" {
		t.Errorf("bob.auth_mode = %q, want bearer", bob.AuthMode)
	}
	if bob.APIKey != "sk-ant-real-key" {
		t.Errorf("bob.api_key = %q, want sk-ant-real-key", bob.APIKey)
	}

	// OAuth providers
	if len(cfg.OAuthProviders) != 1 {
		t.Fatalf("oauth_providers len = %d, want 1", len(cfg.OAuthProviders))
	}
	prov := cfg.OAuthProviders[0]
	if prov.Name != "anthropic" {
		t.Errorf("provider.name = %q, want anthropic", prov.Name)
	}
	if len(prov.Scopes) != 2 {
		t.Errorf("provider.scopes len = %d, want 2", len(prov.Scopes))
	}

	// Observability
	if cfg.Observability.RetentionDays != 30 {
		t.Errorf("retention_days = %d, want 30", cfg.Observability.RetentionDays)
	}
}

// minimalConfig has only the required fields to pass validation; everything
// else should be filled in by applyDefaults.
const minimalConfigTOML = `
[[api_keys]]
key = "sk-min"
name = "min"
enabled = true

[[instances]]
name = "inst-bearer"
auth_mode = "bearer"
api_key = "sk-ant-min"
`

func TestLoadConfig_Defaults(t *testing.T) {
	path := writeTemp(t, minimalConfigTOML)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("host default = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 3000 {
		t.Errorf("port default = %d, want 3000", cfg.Server.Port)
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("log_level default = %q, want info", cfg.Server.LogLevel)
	}
	if cfg.Observability.RetentionDays != 7 {
		t.Errorf("retention_days default = %d, want 7", cfg.Observability.RetentionDays)
	}

	inst := cfg.Instances[0]
	if inst.RequestTimeout != 300 {
		t.Errorf("request_timeout default = %d, want 300", inst.RequestTimeout)
	}
	if inst.MaxConcurrency != 5 {
		t.Errorf("max_concurrency default = %d, want 5", inst.MaxConcurrency)
	}
	if inst.BaseURL != "https://api.anthropic.com" {
		t.Errorf("base_url default = %q, want https://api.anthropic.com", inst.BaseURL)
	}
	if inst.Priority != 1 {
		t.Errorf("priority default = %d, want 1", inst.Priority)
	}
	if inst.Weight != 100 {
		t.Errorf("weight default = %d, want 100", inst.Weight)
	}
	if !inst.IsEnabled() {
		t.Error("instance should be enabled when Enabled field is absent")
	}
}

func TestLoadConfig_Validation(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantErr string
	}{
		{
			name: "no api keys",
			toml: `
[[instances]]
name = "x"
auth_mode = "bearer"
api_key = "sk-key"
`,
			wantErr: "at least one enabled api_key",
		},
		{
			name: "api key disabled",
			toml: `
[[api_keys]]
key = "sk-x"
name = "x"
enabled = false

[[instances]]
name = "x"
auth_mode = "bearer"
api_key = "sk-key"
`,
			wantErr: "at least one enabled api_key",
		},
		{
			name: "no instances",
			toml: `
[[api_keys]]
key = "sk-ok"
name = "ok"
enabled = true
`,
			wantErr: "at least one enabled instance",
		},
		{
			name: "oauth without configured provider",
			toml: `
[[api_keys]]
key = "sk-ok"
name = "ok"
enabled = true

[[instances]]
name = "x"
auth_mode = "oauth"
oauth_provider = "missing-provider"
`,
			wantErr: "unknown oauth_provider",
		},
		{
			name: "bearer without api_key",
			toml: `
[[api_keys]]
key = "sk-ok"
name = "ok"
enabled = true

[[instances]]
name = "x"
auth_mode = "bearer"
`,
			wantErr: "requires non-empty api_key",
		},
		{
			name: "duplicate instance names",
			toml: `
[[api_keys]]
key = "sk-ok"
name = "ok"
enabled = true

[[instances]]
name = "dup"
auth_mode = "bearer"
api_key = "sk-ant-1"

[[instances]]
name = "dup"
auth_mode = "bearer"
api_key = "sk-ant-2"
`,
			wantErr: "duplicate instance name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
