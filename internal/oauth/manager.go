package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type Manager struct {
	mu            sync.RWMutex
	instances     []string // names of oauth instances
	provider      *AnthropicProvider
	store         *TokenStore
	refreshMu     map[string]*sync.Mutex
	proxyResolver func(instanceName string) string // resolves proxy URL per instance
}

// NewManager creates an OAuth manager for the given instance names.
// proxyResolver may be nil if no proxy resolution is needed.
func NewManager(names []string, store *TokenStore, proxyResolver func(string) string) *Manager {
	refreshMu := make(map[string]*sync.Mutex, len(names))
	for _, name := range names {
		refreshMu[name] = &sync.Mutex{}
	}
	instancesCopy := make([]string, len(names))
	copy(instancesCopy, names)
	return &Manager{
		instances:     instancesCopy,
		provider:      NewAnthropicProvider(),
		store:         store,
		refreshMu:     refreshMu,
		proxyResolver: proxyResolver,
	}
}

// UpdateInstances dynamically replaces the instance name list and refresh mutex map.
func (m *Manager) UpdateInstances(names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.instances = make([]string, len(names))
	copy(m.instances, names)
	// Add new mutexes for new instances, keep existing ones.
	for _, name := range names {
		if _, ok := m.refreshMu[name]; !ok {
			m.refreshMu[name] = &sync.Mutex{}
		}
	}
}

// GetValidToken returns a valid access token for the given instance.
// If the token is about to expire (within 60s), it triggers a refresh.
func (m *Manager) GetValidToken(ctx context.Context, instanceName string) (*OAuthToken, error) {
	token, err := m.store.Load(instanceName)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("no token for instance %q, run 'ccproxy oauth login %s'", instanceName, instanceName)
	}

	if time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	return m.refreshToken(ctx, instanceName, token.RefreshToken)
}

// resolveProxy returns the proxy URL for the named instance, or "".
func (m *Manager) resolveProxy(instanceName string) string {
	if m.proxyResolver != nil {
		return m.proxyResolver(instanceName)
	}
	return ""
}

func (m *Manager) refreshToken(ctx context.Context, instanceName, refreshTokenStr string) (*OAuthToken, error) {
	m.mu.RLock()
	mu, ok := m.refreshMu[instanceName]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown instance: %s", instanceName)
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring lock
	token, _ := m.store.Load(instanceName)
	if token != nil && time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	proxyURL := m.resolveProxy(instanceName)
	newToken, err := m.provider.RefreshToken(ctx, refreshTokenStr, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	if err := m.store.Save(instanceName, *newToken); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}

	slog.Info("token refreshed", "instance", instanceName, "expires_at", newToken.ExpiresAt)
	return newToken, nil
}

// Status returns the token info for an instance (without triggering refresh).
func (m *Manager) Status(instanceName string) (*OAuthToken, error) {
	return m.store.Load(instanceName)
}

// Logout removes the stored token for an instance.
func (m *Manager) Logout(instanceName string) error {
	return m.store.Delete(instanceName)
}

// StartAutoRefresh starts a background goroutine that checks and refreshes tokens.
func (m *Manager) StartAutoRefresh(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.mu.RLock()
				names := make([]string, len(m.instances))
				copy(names, m.instances)
				m.mu.RUnlock()
				slog.Debug("oauth: auto-refresh check starting", "instances", len(names))
				for _, name := range names {
					token, err := m.store.Load(name)
					if err != nil {
						slog.Warn("oauth: auto-refresh skipped, token load error", "instance", name, "error", err.Error())
						continue
					}
					if token == nil {
						continue
					}
					remaining := time.Until(token.ExpiresAt)
					if remaining < 60*time.Second {
						slog.Info("oauth: auto-refreshing expiring token", "instance", name, "expires_in", remaining.String())
						_, err := m.refreshToken(ctx, name, token.RefreshToken)
						if err != nil {
							slog.Error("oauth: auto-refresh failed", "instance", name, "error", err.Error())
						}
					}
				}
			}
		}
	}()
}

// GetProvider returns the shared provider (for login flow).
func (m *Manager) GetProvider() *AnthropicProvider {
	return m.provider
}

// GetStore returns the token store.
func (m *Manager) GetStore() *TokenStore {
	return m.store
}
