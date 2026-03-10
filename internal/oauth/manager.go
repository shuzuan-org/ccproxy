package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

type Manager struct {
	providers map[string]*AnthropicProvider
	store     *TokenStore
	refreshMu map[string]*sync.Mutex
}

func NewManager(providerConfigs []config.OAuthProviderConfig, store *TokenStore) *Manager {
	providers := make(map[string]*AnthropicProvider)
	refreshMu := make(map[string]*sync.Mutex)
	for _, cfg := range providerConfigs {
		providers[cfg.Name] = NewAnthropicProvider(cfg)
		refreshMu[cfg.Name] = &sync.Mutex{}
	}
	return &Manager{
		providers: providers,
		store:     store,
		refreshMu: refreshMu,
	}
}

// GetValidToken returns a valid access token for the given provider.
// If the token is about to expire (within 60s), it triggers a refresh.
func (m *Manager) GetValidToken(ctx context.Context, providerName string) (*OAuthToken, error) {
	token, err := m.store.Load(providerName)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("no token for provider %q, run 'ccproxy oauth login %s'", providerName, providerName)
	}

	// Check if token needs refresh (expires within 60 seconds)
	if time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	// Refresh token
	return m.refreshToken(ctx, providerName, token.RefreshToken)
}

func (m *Manager) refreshToken(ctx context.Context, providerName, refreshTokenStr string) (*OAuthToken, error) {
	mu, ok := m.refreshMu[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring lock (another goroutine may have refreshed)
	token, _ := m.store.Load(providerName)
	if token != nil && time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	provider, ok := m.providers[providerName]
	if !ok {
		return nil, fmt.Errorf("unknown provider: %s", providerName)
	}

	newToken, err := provider.RefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	if err := m.store.Save(providerName, *newToken); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}

	slog.Info("token refreshed", "provider", providerName, "expires_at", newToken.ExpiresAt)
	return newToken, nil
}

// Status returns the token info for a provider (without triggering refresh).
func (m *Manager) Status(providerName string) (*OAuthToken, error) {
	return m.store.Load(providerName)
}

// Logout removes the stored token for a provider.
func (m *Manager) Logout(providerName string) error {
	return m.store.Delete(providerName)
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
				for providerName := range m.providers {
					token, err := m.store.Load(providerName)
					if err != nil || token == nil {
						continue
					}
					if time.Until(token.ExpiresAt) < 60*time.Second {
						_, err := m.refreshToken(ctx, providerName, token.RefreshToken)
						if err != nil {
							slog.Error("auto-refresh failed", "provider", providerName, "error", err)
						}
					}
				}
			}
		}
	}()
}

// GetProvider returns the provider by name (for login flow).
func (m *Manager) GetProvider(name string) (*AnthropicProvider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// GetStore returns the token store.
func (m *Manager) GetStore() *TokenStore {
	return m.store
}
