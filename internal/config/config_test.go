package config

import (
	"fmt"
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
	_ = f.Close()
	return f.Name()
}

// validConfig is the canonical "everything present" fixture.
const validConfigTOML = `
[server]
host = "0.0.0.0"
port = 8080
admin_password = "secret"
base_url = "https://api.anthropic.com"
request_timeout = 120
max_concurrency = 3

[[api_keys]]
key = "sk-test-001"
name = "team-a"
enabled = true
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
	if cfg.Server.AdminPassword != "secret" {
		t.Errorf("admin_password = %q, want secret", cfg.Server.AdminPassword)
	}
	if cfg.Server.BaseURL != "https://api.anthropic.com" {
		t.Errorf("base_url = %q, want https://api.anthropic.com", cfg.Server.BaseURL)
	}
	if cfg.Server.RequestTimeout != 120 {
		t.Errorf("request_timeout = %d, want 120", cfg.Server.RequestTimeout)
	}
	if cfg.Server.MaxConcurrency != 3 {
		t.Errorf("max_concurrency = %d, want 3", cfg.Server.MaxConcurrency)
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
}

// minimalConfig has only the required fields to pass validation; everything
// else should be filled in by applyDefaults.
const minimalConfigTOML = `
[server]
admin_password = "test-pass"

[[api_keys]]
key = "sk-min"
name = "min"
enabled = true
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
	if cfg.Server.BaseURL != "https://api.anthropic.com" {
		t.Errorf("base_url default = %q, want https://api.anthropic.com", cfg.Server.BaseURL)
	}
	if cfg.Server.RequestTimeout != 600 {
		t.Errorf("request_timeout default = %d, want 600", cfg.Server.RequestTimeout)
	}
	if cfg.Server.MaxConcurrency != 5 {
		t.Errorf("max_concurrency default = %d, want 5", cfg.Server.MaxConcurrency)
	}
}

func TestValidate_NoEnabledAPIKeys(t *testing.T) {
	// Test Validate() directly to bypass auto-generation in Load()
	cfg := &Config{
		Server: ServerConfig{
			AdminPassword:       "pass",
			UpdateCheckInterval: "1h",
			UpdateChannel:       "stable",
		},
		APIKeys: []APIKeyConfig{
			{Key: "sk-x", Name: "x", Enabled: false},
		},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "at least one enabled api_key") {
		t.Errorf("error = %q, want it to contain 'at least one enabled api_key'", err.Error())
	}
}

func TestLoadConfig_FileNotFound_CreatesDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subdir", "config.toml")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have auto-generated credentials
	if cfg.Server.AdminPassword == "" {
		t.Error("admin_password should have been auto-generated")
	}
	if len(cfg.APIKeys) == 0 {
		t.Fatal("api_keys should have been auto-generated")
	}
	if !strings.HasPrefix(cfg.APIKeys[0].Key, "sk-") {
		t.Errorf("api key %q missing sk- prefix", cfg.APIKeys[0].Key)
	}

	// Default server settings from the generated template
	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", cfg.Server.Host)
	}
	if cfg.Server.Port != 3000 {
		t.Errorf("port = %d, want 3000", cfg.Server.Port)
	}

	// File should exist on disk with generated credentials
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("config file should have been created: %v", err)
	}
	if !strings.Contains(string(data), cfg.Server.AdminPassword) {
		t.Error("generated admin_password not found in config file")
	}
}

func TestLoadConfig_AutoGenerateAdminPassword(t *testing.T) {
	tomlContent := `
[server]
admin_password = ""

[[api_keys]]
key = "sk-ok"
name = "ok"
enabled = true
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tomlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.AdminPassword == "" {
		t.Error("admin_password should have been auto-generated")
	}
	if len(cfg.Server.AdminPassword) != 32 {
		t.Errorf("admin_password length = %d, want 32", len(cfg.Server.AdminPassword))
	}

	// Verify it was persisted to the file
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), cfg.Server.AdminPassword) {
		t.Error("generated admin_password not found in config file")
	}
}

func TestLoadConfig_AutoGenerateAPIKey(t *testing.T) {
	tomlContent := `
[server]
admin_password = "pass"
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tomlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.APIKeys) == 0 {
		t.Fatal("api_keys should have been auto-generated")
	}
	k := cfg.APIKeys[0]
	if !strings.HasPrefix(k.Key, "sk-") {
		t.Errorf("api key %q missing sk- prefix", k.Key)
	}
	if k.Name != "default" {
		t.Errorf("api key name = %q, want default", k.Name)
	}
	if !k.Enabled {
		t.Error("api key should be enabled")
	}

	// Verify it was persisted to the file
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), k.Key) {
		t.Error("generated api key not found in config file")
	}
}

func TestLoadConfig_AutoGenerateBoth(t *testing.T) {
	tomlContent := `
[server]
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tomlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.AdminPassword == "" {
		t.Error("admin_password should have been auto-generated")
	}
	if len(cfg.APIKeys) == 0 {
		t.Fatal("api_keys should have been auto-generated")
	}
}

func TestLoadConfig_DisabledAPIKeysTriggersGenerate(t *testing.T) {
	tomlContent := `
[server]
admin_password = "pass"

[[api_keys]]
key = "sk-x"
name = "x"
enabled = false
`
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(tomlContent), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have the original disabled key plus a new generated one
	if len(cfg.APIKeys) != 2 {
		t.Fatalf("api_keys len = %d, want 2", len(cfg.APIKeys))
	}
	generated := cfg.APIKeys[1]
	if !strings.HasPrefix(generated.Key, "sk-") {
		t.Errorf("generated api key %q missing sk- prefix", generated.Key)
	}
	if !generated.Enabled {
		t.Error("generated api key should be enabled")
	}
}

func TestLoadConfig_NoAutoGenerateWhenPresent(t *testing.T) {
	// Valid config with everything present — nothing should be generated
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(validConfigTOML), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.AdminPassword != "secret" {
		t.Errorf("admin_password = %q, want secret (should not be regenerated)", cfg.Server.AdminPassword)
	}
	if len(cfg.APIKeys) != 1 || cfg.APIKeys[0].Key != "sk-test-001" {
		t.Error("api_keys should not be modified when already present")
	}
}

func TestValidate_PortRange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"too high", 65536, true},
		{"min", 1, false},
		{"max", 65535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Server: ServerConfig{
					AdminPassword:       "pass",
					Port:                tc.port,
					MaxConcurrency:      1,
					RequestTimeout:      1,
					UpdateCheckInterval: "1h",
					UpdateChannel:       "stable",
				},
				APIKeys: []APIKeyConfig{{Key: "sk-x", Enabled: true}},
			}
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_NegativeConcurrency(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server: ServerConfig{
			AdminPassword:       "pass",
			Port:                3000,
			MaxConcurrency:      -1,
			RequestTimeout:      1,
			UpdateCheckInterval: "1h",
			UpdateChannel:       "stable",
		},
		APIKeys: []APIKeyConfig{{Key: "sk-x", Enabled: true}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative max_concurrency")
	}
	if !strings.Contains(err.Error(), "max_concurrency") {
		t.Errorf("error = %q, want max_concurrency mention", err.Error())
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server: ServerConfig{
			AdminPassword:       "pass",
			Port:                3000,
			MaxConcurrency:      1,
			RequestTimeout:      -1,
			UpdateCheckInterval: "1h",
			UpdateChannel:       "stable",
		},
		APIKeys: []APIKeyConfig{{Key: "sk-x", Enabled: true}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative request_timeout")
	}
}

func TestRuntimeAccounts_Multiple(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server: ServerConfig{
			BaseURL:        "https://api.anthropic.com",
			RequestTimeout: 300,
			MaxConcurrency: 5,
		},
	}
	dir := t.TempDir()
	registry := NewAccountRegistry(dir)
	_ = registry.Add("alice")
	_ = registry.Add("bob")

	accounts := cfg.RuntimeAccounts(registry)
	if len(accounts) != 2 {
		t.Fatalf("len = %d, want 2", len(accounts))
	}
	if accounts[0].Name != "alice" || accounts[1].Name != "bob" {
		t.Errorf("names = [%s, %s]", accounts[0].Name, accounts[1].Name)
	}
	for _, a := range accounts {
		if a.MaxConcurrency != 5 {
			t.Errorf("%s: max_concurrency = %d, want 5", a.Name, a.MaxConcurrency)
		}
	}
}

func TestLoad_AutoUpdateDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte("[server]\nadmin_password = \"test123\"\n"), 0o600)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.AutoUpdate == nil {
		t.Fatal("AutoUpdate should not be nil after defaults applied")
	}
	if !*cfg.Server.AutoUpdate {
		t.Error("AutoUpdate default should be true")
	}
	if cfg.Server.UpdateCheckInterval != "1h" {
		t.Errorf("UpdateCheckInterval default = %q, want 1h", cfg.Server.UpdateCheckInterval)
	}
	if cfg.Server.UpdateRepo != "shuzuan-org/ccproxy" {
		t.Errorf("UpdateRepo default = %q, want shuzuan-org/ccproxy", cfg.Server.UpdateRepo)
	}
}

func TestLoad_UpdateCheckIntervalValidation(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		wantErr  bool
	}{
		{"valid 1h", "1h", false},
		{"valid 30m", "30m", false},
		{"too short", "1m", true},
		{"too long", "48h", true},
		{"invalid", "notaduration", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			content := fmt.Sprintf("[server]\nadmin_password = \"test123\"\nupdate_check_interval = %q\n", tt.interval)
			os.WriteFile(cfgPath, []byte(content), 0o600)
			_, err := Load(cfgPath)
			if tt.wantErr && err == nil {
				t.Errorf("expected error for interval %q, got nil", tt.interval)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error for interval %q: %v", tt.interval, err)
			}
		})
	}
}

func TestApplyDefaults_UpdateChannel(t *testing.T) {
	t.Parallel()
	cfg := &Config{}
	cfg.applyDefaults()
	if cfg.Server.UpdateChannel != "stable" {
		t.Errorf("expected default UpdateChannel \"stable\", got %q", cfg.Server.UpdateChannel)
	}
}

func TestApplyDefaults_UpdateChannel_PreservesExisting(t *testing.T) {
	t.Parallel()
	cfg := &Config{Server: ServerConfig{UpdateChannel: "beta"}}
	cfg.applyDefaults()
	if cfg.Server.UpdateChannel != "beta" {
		t.Errorf("expected UpdateChannel \"beta\" preserved, got %q", cfg.Server.UpdateChannel)
	}
}

// baseValidConfig returns a minimal valid Config for Validate() tests.
func baseValidConfig() *Config {
	return &Config{
		Server: ServerConfig{
			AdminPassword:       "secret",
			Port:                3000,
			MaxConcurrency:      1,
			RequestTimeout:      1,
			UpdateCheckInterval: "1h",
			UpdateChannel:       "stable",
		},
		APIKeys: []APIKeyConfig{
			{Key: "sk-test", Name: "test", Enabled: true},
		},
	}
}

func TestValidate_UpdateChannel_Invalid(t *testing.T) {
	t.Parallel()
	cfg := baseValidConfig()
	cfg.Server.UpdateChannel = "nightly"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid update_channel, got nil")
	}
	if !strings.Contains(err.Error(), "update_channel") {
		t.Errorf("error %q should mention update_channel", err.Error())
	}
}

func TestValidate_UpdateChannel_Beta(t *testing.T) {
	t.Parallel()
	cfg := baseValidConfig()
	cfg.Server.UpdateChannel = "beta"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error for channel \"beta\", got %v", err)
	}
}

func TestValidate_UpdateChannel_Stable(t *testing.T) {
	t.Parallel()
	cfg := baseValidConfig()
	cfg.Server.UpdateChannel = "stable"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error for channel \"stable\", got %v", err)
	}
}

func TestRuntimeAccount(t *testing.T) {
	cfg := &Config{
		Server: ServerConfig{
			BaseURL:        "https://api.anthropic.com",
			RequestTimeout: 120,
			MaxConcurrency: 3,
		},
	}

	acct := cfg.RuntimeAccount(Account{Name: "alice", Enabled: true, Proxy: "socks5://127.0.0.1:1080"})
	if acct.Name != "alice" {
		t.Errorf("name = %q, want alice", acct.Name)
	}
	if acct.MaxConcurrency != 3 {
		t.Errorf("max_concurrency = %d, want 3", acct.MaxConcurrency)
	}
	if acct.BaseURL != "https://api.anthropic.com" {
		t.Errorf("base_url = %q", acct.BaseURL)
	}
	if acct.RequestTimeout != 120 {
		t.Errorf("request_timeout = %d, want 120", acct.RequestTimeout)
	}
	if !acct.IsEnabled() {
		t.Error("should be enabled")
	}
	if acct.Proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://127.0.0.1:1080", acct.Proxy)
	}
}
