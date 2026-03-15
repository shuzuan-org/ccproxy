package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/observe"
)

type Manager struct {
	mu            sync.RWMutex
	accounts     []string // names of oauth accounts
	provider      *AnthropicProvider
	store         *TokenStore
	refreshMu     map[string]*sync.Mutex
	proxyResolver func(accountName string) string // resolves proxy URL per account
}

// NewManager creates an OAuth manager for the given account names.
// proxyResolver may be nil if no proxy resolution is needed.
func NewManager(names []string, store *TokenStore, proxyResolver func(string) string) *Manager {
	refreshMu := make(map[string]*sync.Mutex, len(names))
	for _, name := range names {
		refreshMu[name] = &sync.Mutex{}
	}
	accountsCopy := make([]string, len(names))
	copy(accountsCopy, names)
	return &Manager{
		accounts:     accountsCopy,
		provider:      NewAnthropicProvider(),
		store:         store,
		refreshMu:     refreshMu,
		proxyResolver: proxyResolver,
	}
}

// UpdateAccounts dynamically replaces the account name list and refresh mutex map.
func (m *Manager) UpdateAccounts(names []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accounts = make([]string, len(names))
	copy(m.accounts, names)
	// Add new mutexes for new accounts, keep existing ones.
	for _, name := range names {
		if _, ok := m.refreshMu[name]; !ok {
			m.refreshMu[name] = &sync.Mutex{}
		}
	}
}

// GetValidToken returns a valid access token for the given account.
// If the token is about to expire (within 60s), it triggers a refresh.
func (m *Manager) GetValidToken(ctx context.Context, accountName string) (*OAuthToken, error) {
	token, err := m.store.Load(accountName)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("no token for account %q, run 'ccproxy oauth login %s'", accountName, accountName)
	}

	if time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	return m.refreshToken(ctx, accountName, token.RefreshToken)
}

// resolveProxy returns the proxy URL for the named account, or "".
func (m *Manager) resolveProxy(accountName string) string {
	if m.proxyResolver != nil {
		return m.proxyResolver(accountName)
	}
	return ""
}

func (m *Manager) refreshToken(ctx context.Context, accountName, refreshTokenStr string) (*OAuthToken, error) {
	m.mu.RLock()
	mu, ok := m.refreshMu[accountName]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown account: %s", accountName)
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring lock
	token, _ := m.store.Load(accountName)
	if token != nil && time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	// Re-read refresh token from store after acquiring lock to avoid using
	// a stale token that was already rotated by another goroutine.
	freshToken, _ := m.store.Load(accountName)
	if freshToken == nil || freshToken.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available for %s", accountName)
	}

	proxyURL := m.resolveProxy(accountName)
	newToken, err := m.provider.RefreshToken(ctx, freshToken.RefreshToken, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	if err := m.store.Save(accountName, *newToken); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}

	observe.Logger(ctx).Info("token refreshed", "account", accountName, "expires_at", newToken.ExpiresAt)
	return newToken, nil
}

// ForceRefresh forces a token refresh for the named account with concurrency protection.
func (m *Manager) ForceRefresh(ctx context.Context, accountName string) (*OAuthToken, error) {
	token, err := m.store.Load(accountName)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("no token stored for account %q", accountName)
	}
	if token.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available for account %q", accountName)
	}

	m.mu.RLock()
	mu, ok := m.refreshMu[accountName]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown account: %s", accountName)
	}

	mu.Lock()
	defer mu.Unlock()

	proxyURL := m.resolveProxy(accountName)
	newToken, err := m.provider.RefreshToken(ctx, token.RefreshToken, proxyURL)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	if err := m.store.Save(accountName, *newToken); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}

	observe.Logger(ctx).Info("token force-refreshed", "account", accountName, "expires_at", newToken.ExpiresAt)
	return newToken, nil
}

// ExchangeAndSave exchanges an authorization code for tokens and saves the result.
func (m *Manager) ExchangeAndSave(ctx context.Context, accountName, code, verifier, proxyURL string) (*OAuthToken, error) {
	token, err := m.provider.ExchangeCode(ctx, code, verifier, proxyURL)
	if err != nil {
		return nil, err
	}
	if err := m.store.Save(accountName, *token); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}
	return token, nil
}

// Status returns the token info for an account (without triggering refresh).
func (m *Manager) Status(accountName string) (*OAuthToken, error) {
	return m.store.Load(accountName)
}

// Logout removes the stored token for an account.
func (m *Manager) Logout(accountName string) error {
	return m.store.Delete(accountName)
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
				names := make([]string, len(m.accounts))
				copy(names, m.accounts)
				m.mu.RUnlock()
				slog.Debug("oauth: auto-refresh check starting", "accounts", len(names))
				for _, name := range names {
					token, err := m.store.Load(name)
					if err != nil {
						slog.Warn("oauth: auto-refresh skipped, token load error", "account", name, "error", err.Error())
						continue
					}
					if token == nil {
						continue
					}
					remaining := time.Until(token.ExpiresAt)
					if remaining < 60*time.Second {
						slog.Info("oauth: auto-refreshing expiring token", "account", name, "expires_in", remaining.String())
						_, err := m.refreshToken(ctx, name, token.RefreshToken)
						if err != nil {
							slog.Error("oauth: auto-refresh failed", "account", name, "error", err.Error())
						}
					} else if remaining < 2*time.Minute {
						slog.Warn("oauth: token expiring soon",
							"account", name,
							"expires_in", remaining.Round(time.Second),
						)
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

// MarkTokenExpired immediately marks the stored token for an account as expired.
// This causes the next GetValidToken call to trigger a refresh.
func (m *Manager) MarkTokenExpired(accountName string) {
	token, err := m.store.Load(accountName)
	if err != nil || token == nil {
		return
	}
	token.ExpiresAt = time.Now()
	_ = m.store.Save(accountName, *token)
	slog.Info("token marked as expired", "account", accountName)
}

// ForceRefreshBackground triggers a token refresh in a background goroutine.
func (m *Manager) ForceRefreshBackground(ctx context.Context, accountName string) {
	go func() {
		_, err := m.ForceRefresh(ctx, accountName)
		if err != nil {
			slog.Warn("background token refresh failed", "account", accountName, "error", err.Error())
		}
	}()
}
