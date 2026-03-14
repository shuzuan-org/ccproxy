package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Server  ServerConfig   `toml:"server"`
	APIKeys []APIKeyConfig `toml:"api_keys"`
}

type ServerConfig struct {
	Host           string `toml:"host"`
	Port           int    `toml:"port"`
	AdminPassword  string `toml:"admin_password"`
	RateLimit      int    `toml:"rate_limit"`       // max requests per minute per IP for admin routes
	BaseURL        string `toml:"base_url"`          // upstream API base URL (default: https://api.anthropic.com)
	RequestTimeout int    `toml:"request_timeout"`   // seconds (default: 300)
	MaxConcurrency int    `toml:"max_concurrency"`   // per-instance concurrency limit (default: 5)
	LogLevel       string `toml:"log_level"`         // debug, info, warn, error (default: info)
	LogFormat      string `toml:"log_format"`        // text or json (default: text)
}

type APIKeyConfig struct {
	Key     string `toml:"key"`
	Name    string `toml:"name"`
	Enabled bool   `toml:"enabled"`
}

// InstanceConfig is the runtime representation of an instance, built from
// global config + registry entry. Not parsed from TOML directly.
type InstanceConfig struct {
	Name           string
	MaxConcurrency int
	BaseURL        string
	RequestTimeout int
	Enabled        bool
	Proxy          string // SOCKS5 proxy URL for this instance (e.g. "socks5://host:port")
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
host = "0.0.0.0"
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
		cfg.Server.RequestTimeout = 300
	}
	if cfg.Server.MaxConcurrency == 0 {
		cfg.Server.MaxConcurrency = 5
	}
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}
	if cfg.Server.LogFormat == "" {
		cfg.Server.LogFormat = "text"
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

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// SetupLoggingDefaults initializes slog with sensible defaults (text, info level)
// before config is parsed. config.Load() calls SetupLogging() again with the
// actual configured values once the TOML is parsed.
func SetupLoggingDefaults() {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
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

	var handler slog.Handler
	if strings.ToLower(cfg.Server.LogFormat) == "json" {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	slog.SetDefault(slog.New(handler))
}

// IsEnabled returns true when the instance is enabled.
func (ic *InstanceConfig) IsEnabled() bool {
	return ic.Enabled
}

// RuntimeInstance builds a full InstanceConfig from global settings + a registry entry.
func (c *Config) RuntimeInstance(inst Instance) InstanceConfig {
	return InstanceConfig{
		Name:           inst.Name,
		MaxConcurrency: c.Server.MaxConcurrency,
		BaseURL:        c.Server.BaseURL,
		RequestTimeout: c.Server.RequestTimeout,
		Enabled:        inst.Enabled,
		Proxy:          inst.Proxy,
	}
}

// RuntimeInstances builds all InstanceConfigs from a registry.
func (c *Config) RuntimeInstances(registry *InstanceRegistry) []InstanceConfig {
	entries := registry.List()
	result := make([]InstanceConfig, 0, len(entries))
	for _, e := range entries {
		result = append(result, c.RuntimeInstance(e))
	}
	return result
}

