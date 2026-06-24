package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// clientIDOverridePattern matches the 64-char lowercase hex ClientID format
// produced by disguise.GenerateClientID — keep these in lockstep.
var clientIDOverridePattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Config struct {
	Server           ServerConfig      `toml:"server"`
	APIKeys          []APIKeyConfig    `toml:"api_keys"`
	Pools            []PoolConfig      `toml:"pools"`
	AccountOverrides []AccountOverride `toml:"account_overrides"`
}

// AccountOverride pins a specific account's disguise ClientID (used as
// metadata.user_id.device_id) to a fixed value. This lets the operator make
// a real local Claude Code client and its corresponding proxy account share
// the same device_id by copying ~/.claude.json:userID into client_id.
//
// Matched by display name against AccountRegistry — accounts can be added
// later via the admin UI, so an override referencing a not-yet-existing
// account is allowed and applied lazily on first fingerprint creation.
type AccountOverride struct {
	AccountName string `toml:"account_name"`
	ClientID    string `toml:"client_id"`
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
	UpdateAPIURL        string `toml:"update_api_url"`        // GitHub Enterprise API URL (default: github.com)
	UpdateChannel       string `toml:"update_channel"`        // "stable" (default) or "beta"
}

// IsAutoUpdateEnabled returns true when auto-update is enabled (default: true when AutoUpdate is nil).
func (s ServerConfig) IsAutoUpdateEnabled() bool {
	if s.AutoUpdate == nil {
		return true
	}
	return *s.AutoUpdate
}

type APIKeyConfig struct {
	Key      string `toml:"key"`
	Name     string `toml:"name"`
	Password string `toml:"password"`
	Enabled  bool   `toml:"enabled"`
	// Scheduling declares which accounts this key can dispatch to.
	// Entries accept prefixes: "self", "owner:<name>", "pool:<name>", "*", "unowned".
	// Empty or unset defaults to ["*"] (global pool, backwards compatible).
	Scheduling []string `toml:"scheduling"`
}

// PoolConfig is a named group of usernames. It is a configuration-level
// reuse mechanism, not a runtime entity: pool references are expanded to
// their member list at config load time.
type PoolConfig struct {
	Name    string   `toml:"name"`
	Members []string `toml:"members"`
}

// AccountConfig is the runtime representation of an account, built from
// global config + registry entry. Not parsed from TOML directly.
type AccountConfig struct {
	ID             string
	Name           string
	MaxConcurrency int
	BaseURL        string
	RequestTimeout int
	Enabled        bool
	Proxy          string // SOCKS5 proxy URL for this account (e.g. "socks5://host:port" or "socks5h://host:port")
	Owner          string // API key name of the account creator; empty for legacy/migrated records
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

	cfg.applyDefaults()

	// Initialize logging early so all subsequent log output uses the configured format/level.
	SetupLogging(cfg)

	genPassword, genKeys, genPasswords := autoGenerate(cfg, path)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if genPassword || genKeys || len(genPasswords) > 0 {
		printGeneratedCredentials(cfg, genPassword, genKeys, genPasswords)
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
func (cfg *Config) applyDefaults() {
	// Server defaults
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
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
	if cfg.Server.UpdateChannel == "" {
		cfg.Server.UpdateChannel = "stable"
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

	if c.Server.UpdateChannel != "stable" && c.Server.UpdateChannel != "beta" {
		errs = append(errs, fmt.Errorf("update_channel must be \"stable\" or \"beta\", got %q", c.Server.UpdateChannel))
	}

	// Scheduling: pool references must resolve and entry syntax must be valid.
	// Pool members and owner: directives are matched against api_key names
	// case-sensitively — fail fast if they don't resolve to a known key so
	// a typo doesn't turn into a silent 503 at request time.
	knownKeys := make(map[string]bool, len(c.APIKeys))
	for _, k := range c.APIKeys {
		if k.Name != "" {
			knownKeys[k.Name] = true
		}
	}
	poolNames := make(map[string]bool, len(c.Pools))
	for _, p := range c.Pools {
		if p.Name == "" {
			errs = append(errs, errors.New("pool name must not be empty"))
			continue
		}
		if poolNames[p.Name] {
			errs = append(errs, fmt.Errorf("duplicate pool name %q", p.Name))
		}
		poolNames[p.Name] = true
		for _, m := range p.Members {
			if m == "" {
				continue
			}
			if !knownKeys[m] {
				// A pool member that is not a known api_key name cannot
				// match any account.Owner (owners are always api_key names
				// at creation time), so the pool silently filters to empty
				// for every key that references it. Refuse to start
				// instead of surfacing this at request time. This also
				// catches the case-sensitivity footgun: "Alice" will not
				// match an api_key named "alice".
				errs = append(errs, fmt.Errorf("pool %q references unknown api_key %q (pool members must be existing api_key names; match is case-sensitive)", p.Name, m))
			}
		}
	}
	for _, k := range c.APIKeys {
		scope, err := ResolveScheduling(k.Name, k.Scheduling, c.Pools)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Fail fast if the resolved scope is empty (non-AllowAll with no
		// owners and no unowned flag). Without this check the error only
		// surfaces on the first request as a 503, which is confusing.
		if scope != nil && !scope.AllowAll && len(scope.AllowedOwners) == 0 && !scope.AllowUnowned {
			errs = append(errs, fmt.Errorf("api_key %q: scheduling scope is empty (no allowed owners)", k.Name))
			continue
		}
		// owner:<name> references must also resolve to a known api_key, for
		// the same case-sensitivity + typo reasons that apply to pools.
		if scope != nil && !scope.AllowAll {
			for owner := range scope.AllowedOwners {
				if !knownKeys[owner] {
					errs = append(errs, fmt.Errorf("api_key %q: scheduling references unknown owner %q (match is case-sensitive)", k.Name, owner))
				}
			}
		}
	}

	// account_overrides: pin specific accounts to a fixed disguise ClientID.
	// Validate format only — existence in AccountRegistry is intentionally NOT
	// checked, since accounts are added dynamically via admin UI.
	overrideNames := make(map[string]bool, len(c.AccountOverrides))
	for i, o := range c.AccountOverrides {
		if o.AccountName == "" {
			errs = append(errs, fmt.Errorf("account_overrides[%d]: account_name must not be empty", i))
			continue
		}
		if overrideNames[o.AccountName] {
			errs = append(errs, fmt.Errorf("account_overrides: duplicate account_name %q", o.AccountName))
			continue
		}
		overrideNames[o.AccountName] = true
		if !clientIDOverridePattern.MatchString(o.ClientID) {
			errs = append(errs, fmt.Errorf("account_overrides[%q]: client_id must be 64 lowercase hex chars, got %q", o.AccountName, o.ClientID))
		}
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

// AccountOverrideByName returns the configured ClientID override for the given
// account display name, or "", false if no override is configured.
func (c *Config) AccountOverrideByName(name string) (string, bool) {
	for _, o := range c.AccountOverrides {
		if o.AccountName == name {
			return o.ClientID, true
		}
	}
	return "", false
}

// RuntimeAccount builds a full AccountConfig from global settings + a registry entry.
func (c *Config) RuntimeAccount(acct Account) AccountConfig {
	return AccountConfig{
		ID:             acct.ID,
		Name:           acct.Name,
		MaxConcurrency: c.Server.MaxConcurrency,
		BaseURL:        c.Server.BaseURL,
		RequestTimeout: c.Server.RequestTimeout,
		Enabled:        acct.Enabled,
		Proxy:          acct.Proxy,
		Owner:          acct.Owner,
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
