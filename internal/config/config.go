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
	Server         ServerConfig          `toml:"server"`
	APIKeys        []APIKeyConfig        `toml:"api_keys"`
	Instances      []InstanceConfig      `toml:"instances"`
	OAuthProviders []OAuthProviderConfig `toml:"oauth_providers"`
	Observability  ObservabilityConfig   `toml:"observability"`
}

type ServerConfig struct {
	Host          string `toml:"host"`
	Port          int    `toml:"port"`
	LogLevel      string `toml:"log_level"`
	AdminPassword string `toml:"admin_password"`
}

type APIKeyConfig struct {
	Key     string `toml:"key"`
	Name    string `toml:"name"`
	Enabled bool   `toml:"enabled"`
}

type InstanceConfig struct {
	Name           string `toml:"name"`
	AuthMode       string `toml:"auth_mode"`      // "oauth" | "bearer"
	OAuthProvider  string `toml:"oauth_provider"`
	APIKey         string `toml:"api_key"`
	Priority       int    `toml:"priority"`
	Weight         int    `toml:"weight"`
	MaxConcurrency int    `toml:"max_concurrency"`
	BaseURL        string `toml:"base_url"`
	RequestTimeout int    `toml:"request_timeout"` // seconds
	TLSFingerprint bool   `toml:"tls_fingerprint"`
	Enabled        *bool  `toml:"enabled"` // default true
}

type OAuthProviderConfig struct {
	Name        string   `toml:"name"`
	ClientID    string   `toml:"client_id"`
	AuthURL     string   `toml:"auth_url"`
	TokenURL    string   `toml:"token_url"`
	RedirectURI string   `toml:"redirect_uri"`
	Scopes      []string `toml:"scopes"`
}

type ObservabilityConfig struct {
	RetentionDays int `toml:"retention_days"`
}

// Load reads, parses, applies defaults, and validates the config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	applyDefaults(cfg)

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
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
	if cfg.Server.LogLevel == "" {
		cfg.Server.LogLevel = "info"
	}

	// Observability defaults
	if cfg.Observability.RetentionDays == 0 {
		cfg.Observability.RetentionDays = 7
	}

	// Instance defaults
	for i := range cfg.Instances {
		inst := &cfg.Instances[i]
		if inst.RequestTimeout == 0 {
			inst.RequestTimeout = 300
		}
		if inst.MaxConcurrency == 0 {
			inst.MaxConcurrency = 5
		}
		if inst.BaseURL == "" {
			inst.BaseURL = "https://api.anthropic.com"
		}
		if inst.Priority == 0 {
			inst.Priority = 1
		}
		if inst.Weight == 0 {
			inst.Weight = 100
		}
	}
}

// Validate checks all business rules and returns an error describing
// the first (or combined) violation found.
func (c *Config) Validate() error {
	var errs []error

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

	// At least 1 enabled instance
	enabledInstances := 0
	for _, inst := range c.Instances {
		if inst.IsEnabled() {
			enabledInstances++
		}
	}
	if enabledInstances == 0 {
		errs = append(errs, errors.New("at least one enabled instance is required"))
	}

	// Build oauth provider name set for reference checks
	oauthProviders := make(map[string]struct{}, len(c.OAuthProviders))
	for _, p := range c.OAuthProviders {
		oauthProviders[p.Name] = struct{}{}
	}

	// Instance-level validations
	names := make(map[string]struct{}, len(c.Instances))
	for _, inst := range c.Instances {
		// Unique names
		if _, dup := names[inst.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate instance name: %q", inst.Name))
		}
		names[inst.Name] = struct{}{}

		// OAuth instances must reference a configured provider
		if inst.IsOAuth() {
			if _, ok := oauthProviders[inst.OAuthProvider]; !ok {
				errs = append(errs, fmt.Errorf(
					"instance %q references unknown oauth_provider %q", inst.Name, inst.OAuthProvider,
				))
			}
		}

		// Bearer instances must have a non-empty api_key
		if inst.AuthMode == "bearer" && inst.APIKey == "" {
			errs = append(errs, fmt.Errorf("instance %q (bearer) requires non-empty api_key", inst.Name))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// IsOAuth returns true when the instance uses OAuth authentication.
func (ic *InstanceConfig) IsOAuth() bool {
	return ic.AuthMode == "oauth"
}

// IsEnabled returns true when Enabled is nil (default on) or explicitly true.
func (ic *InstanceConfig) IsEnabled() bool {
	return ic.Enabled == nil || *ic.Enabled
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
		watcher.Close()
		return nil, fmt.Errorf("watch directory: %w", err)
	}

	done := make(chan struct{})
	go func() {
		defer watcher.Close()

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
