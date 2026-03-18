package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server  ServerConfig   `toml:"server"`
	APIKeys []APIKeyConfig `toml:"api_keys"`
}

type ServerConfig struct {
	Host                string `toml:"host"`
	Port                int    `toml:"port"`
	AdminPassword       string `toml:"admin_password"`
	RateLimit           int    `toml:"rate_limit"`            // max requests per minute per IP for admin routes
	BaseURL             string `toml:"base_url"`              // upstream API base URL (default: https://api.anthropic.com)
	RequestTimeout      int    `toml:"request_timeout"`       // seconds (default: 600, aligned with Claude Code's X-Stainless-Timeout)
	MaxConcurrency      int    `toml:"max_concurrency"`       // per-account concurrency hard limit; actual value is dynamically adjusted by budget utilization (default: 5)
	LogLevel            string `toml:"log_level"`             // debug, info, warn, error (default: info)
	AutoUpdate          *bool  `toml:"auto_update"`           // nil = true (default); pointer to distinguish unset from false
	UpdateCheckInterval string `toml:"update_check_interval"` // duration string, e.g. "1h", "30m"
	UpdateRepo          string `toml:"update_repo"`           // GitHub owner/repo
}

// IsAutoUpdateEnabled returns true when auto-update is enabled (default: true when AutoUpdate is nil).
func (s ServerConfig) IsAutoUpdateEnabled() bool {
	if s.AutoUpdate == nil {
		return true
	}
	return *s.AutoUpdate
}

type APIKeyConfig struct {
	Key     string `toml:"key"`
	Name    string `toml:"name"`
	Enabled bool   `toml:"enabled"`
}

// AccountConfig is the runtime representation of an account, built from
// global config + registry entry. Not parsed from TOML directly.
type AccountConfig struct {
	Name           string
	MaxConcurrency int
	BaseURL        string
	RequestTimeout int
	Enabled        bool
	Proxy          string // SOCKS5 proxy URL for this account (e.g. "socks5://host:port")
}

// Load reads, parses, applies defaults, auto-generates missing credentials,
// and validates the config file at path. If the file does not exist, a
// default config is created automatically.
func Load(path string) (*Config, error) {
	if err := ensureConfigFile(path); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	applyDefaults(cfg)

	// Initialize logging early so all subsequent log output uses the configured format/level.
	SetupLogging(cfg)

	genPassword, genKey := autoGenerate(cfg, path)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if genPassword || genKey {
		printGeneratedCredentials(cfg, genPassword, genKey)
	}

	return cfg, nil
}

// defaultConfigContent is the template written when no config file exists.
const defaultConfigContent = `[server]
host = "127.0.0.1"
port = 3000
`

// ensureConfigFile creates a minimal config file if it does not exist,
// including any parent directories needed.
func ensureConfigFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil // file exists
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check config file: %w", err)
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create config directory: %w", err)
		}
	}

	slog.Info("config file not found, creating default", "path", path)
	if err := os.WriteFile(path, []byte(defaultConfigContent), 0o600); err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	return nil
}

// applyDefaults fills in zero-value fields with sensible defaults.
func applyDefaults(cfg *Config) {
	// Server defaults
	if cfg.Server.Host == "" {
		cfg.Server.Host = "127.0.0.1"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 3000
	}
	if cfg.Server.RateLimit == 0 {
		cfg.Server.RateLimit = 60
	}
	if cfg.Server.BaseURL == "" {
		cfg.Server.BaseURL = "https://api.anthropic.com"
	}
	if cfg.Server.RequestTimeout == 0 {
		cfg.Server.RequestTimeout = 600
	}
	if cfg.Server.MaxConcurrency == 0 {
		cfg.Server.MaxConcurrency = 5
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}
	if cfg.Server.AutoUpdate == nil {
		t := true
		cfg.Server.AutoUpdate = &t
	}
	if cfg.Server.UpdateCheckInterval == "" {
		cfg.Server.UpdateCheckInterval = "1h"
	}
	if cfg.Server.UpdateRepo == "" {
		cfg.Server.UpdateRepo = "shuzuan-org/ccproxy"
	}
}

// Validate checks all business rules and returns an error describing
// the first (or combined) violation found.
func (c *Config) Validate() error {
	var errs []error

	// Admin password is required for security.
	if c.Server.AdminPassword == "" {
		errs = append(errs, errors.New("server.admin_password is required"))
	}

	// Field range checks
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Errorf("port must be between 1 and 65535, got %d", c.Server.Port))
	}
	if c.Server.MaxConcurrency < 1 {
		errs = append(errs, fmt.Errorf("max_concurrency must be >= 1, got %d", c.Server.MaxConcurrency))
	}
	if c.Server.RequestTimeout < 1 {
		errs = append(errs, fmt.Errorf("request_timeout must be >= 1, got %d", c.Server.RequestTimeout))
	}
	if c.Server.RateLimit < 0 {
		errs = append(errs, fmt.Errorf("rate_limit must be >= 0, got %d", c.Server.RateLimit))
	}

	// At least 1 enabled API key
	enabledKeys := 0
	for _, k := range c.APIKeys {
		if k.Enabled {
			enabledKeys++
		}
	}
	if enabledKeys == 0 {
		errs = append(errs, errors.New("at least one enabled api_key is required"))
	}

	d, parseErr := time.ParseDuration(c.Server.UpdateCheckInterval)
	if parseErr != nil {
		errs = append(errs, fmt.Errorf("invalid update_check_interval %q: %w", c.Server.UpdateCheckInterval, parseErr))
	} else if d < 5*time.Minute {
		errs = append(errs, fmt.Errorf("update_check_interval must be >= 5m, got %s", d))
	} else if d > 24*time.Hour {
		errs = append(errs, fmt.Errorf("update_check_interval must be <= 24h, got %s", d))
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SetupLoggingDefaults initializes slog with sensible defaults (JSON, info level)
// before config is parsed. config.Load() calls SetupLogging() again with the
// actual configured values once the TOML is parsed.
func SetupLoggingDefaults() {
	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
}

// SetupLogging configures the global slog logger based on config values.
func SetupLogging(cfg *Config) {
	var level slog.Level
	switch strings.ToLower(cfg.Server.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	handler := slog.NewJSONHandler(os.Stderr, opts)
	slog.SetDefault(slog.New(handler))
}

// IsEnabled returns true when the account is enabled.
func (ac *AccountConfig) IsEnabled() bool {
	return ac.Enabled
}

// RuntimeAccount builds a full AccountConfig from global settings + a registry entry.
func (c *Config) RuntimeAccount(acct Account) AccountConfig {
	return AccountConfig{
		Name:           acct.Name,
		MaxConcurrency: c.Server.MaxConcurrency,
		BaseURL:        c.Server.BaseURL,
		RequestTimeout: c.Server.RequestTimeout,
		Enabled:        acct.Enabled,
		Proxy:          acct.Proxy,
	}
}

// RuntimeAccounts builds all AccountConfigs from a registry.
func (c *Config) RuntimeAccounts(registry *AccountRegistry) []AccountConfig {
	entries := registry.List()
	result := make([]AccountConfig, 0, len(entries))
	for _, e := range entries {
		result = append(result, c.RuntimeAccount(e))
	}
	return result
}
