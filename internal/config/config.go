package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fsnotify/fsnotify"
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
	Enabled        *bool
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

	log.Printf("config file not found, creating default at %s", path)
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
}

// Validate checks all business rules and returns an error describing
// the first (or combined) violation found.
func (c *Config) Validate() error {
	var errs []error

	// Admin password is required for security.
	if c.Server.AdminPassword == "" {
		errs = append(errs, errors.New("server.admin_password is required"))
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

// IsEnabled returns true when Enabled is nil (default on) or explicitly true.
func (ic *InstanceConfig) IsEnabled() bool {
	return ic.Enabled == nil || *ic.Enabled
}

// RuntimeInstance builds a full InstanceConfig from global settings + a registry entry.
func (c *Config) RuntimeInstance(name string, enabled bool) InstanceConfig {
	return InstanceConfig{
		Name:           name,
		MaxConcurrency: c.Server.MaxConcurrency,
		BaseURL:        c.Server.BaseURL,
		RequestTimeout: c.Server.RequestTimeout,
		Enabled:        &enabled,
	}
}

// RuntimeInstances builds all InstanceConfigs from a registry.
func (c *Config) RuntimeInstances(registry *InstanceRegistry) []InstanceConfig {
	entries := registry.List()
	result := make([]InstanceConfig, 0, len(entries))
	for _, e := range entries {
		result = append(result, c.RuntimeInstance(e.Name, e.Enabled))
	}
	return result
}

// Watch starts watching the config file for changes.
// On change, reloads and validates config, then calls onChange callback.
// Returns a stop function and any error.
func Watch(path string, onChange func(*Config)) (stop func(), err error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}

	// Watch the directory (not the file directly) to handle editors that
	// delete+recreate files (vim, etc.)
	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("watch directory: %w", err)
	}

	done := make(chan struct{})
	go func() {
		defer func() { _ = watcher.Close() }()

		// Debounce timer to avoid reloading on rapid file changes
		var debounceTimer *time.Timer

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Only react to writes/creates for our config file
				if filepath.Base(event.Name) != filepath.Base(path) {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}

				// Debounce: wait 500ms after last change before reloading
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
					cfg, err := Load(path)
					if err != nil {
						log.Printf("config reload failed: %v", err)
						return
					}
					log.Printf("config reloaded from %s", path)
					onChange(cfg)
				})

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("config watcher error: %v", err)

			case <-done:
				return
			}
		}
	}()

	var once sync.Once
	stopFn := func() {
		// Use sync.Once to make stop idempotent; calling it multiple times is safe.
		once.Do(func() {
			close(done)
		})
	}

	return stopFn, nil
}
