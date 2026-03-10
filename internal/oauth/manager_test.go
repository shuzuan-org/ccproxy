package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

// newTestManager creates a Manager backed by a temp TokenStore and pointing to
// the given token server URL.
func newTestManager(t *testing.T, tokenServerURL string) (*Manager, *TokenStore) {
	t.Helper()
	store, err := NewTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	cfg := []config.OAuthProviderConfig{
		{
			Name:        "anthropic",
			ClientID:    "test-client",
			AuthURL:     "https://auth.example.com/oauth/authorize",
			TokenURL:    tokenServerURL,
			RedirectURI: "http://localhost:8080/callback",
			Scopes:      []string{"user:inference"},
		},
	}
	m := NewManager(cfg, store)
	return m, store
}

// mockTokenServer returns an httptest.Server that responds with a token JSON.
func mockTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-access",
			"refresh_token": "new-refresh",
			"expires_in":    3600,
			"scope":         "user:inference",
		})
	}))
}

func TestManager_GetValidToken_FreshToken(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	// Save a fresh token (expires in 10 minutes — well beyond 60s threshold)
	tok := OAuthToken{
		AccessToken:  "cached-access",
		RefreshToken: "cached-refresh",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
		Scope:        "user:inference",
	}
	if err := store.Save("anthropic", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := m.GetValidToken(context.Background(), "anthropic")
	if err != nil {
		t.Fatalf("GetValidToken: %v", err)
	}
	// Should return cached token without hitting the token server
	if got.AccessToken != "cached-access" {
		t.Errorf("expected cached-access, got %q", got.AccessToken)
	}
}

func TestManager_GetValidToken_ExpiredToken_TriggersRefresh(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	// Save a token that expires in 30s (below 60s threshold)
	tok := OAuthToken{
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(30 * time.Second),
		Scope:        "user:inference",
	}
	if err := store.Save("anthropic", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := m.GetValidToken(context.Background(), "anthropic")
	if err != nil {
		t.Fatalf("GetValidToken: %v", err)
	}
	// Should have refreshed and returned the new token
	if got.AccessToken != "new-access" {
		t.Errorf("expected new-access, got %q", got.AccessToken)
	}
}

func TestManager_GetValidToken_NoToken_ReturnsError(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.GetValidToken(context.Background(), "anthropic")
	if err == nil {
		t.Fatal("expected error when no token stored")
	}
	if !strings.Contains(err.Error(), "ccproxy oauth login") {
		t.Errorf("expected login hint in error, got: %v", err)
	}
}

func TestManager_Status_ReturnsTokenWithoutRefresh(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	// Store an almost-expired token
	tok := OAuthToken{
		AccessToken:  "status-access",
		RefreshToken: "status-refresh",
		ExpiresAt:    time.Now().Add(10 * time.Second),
		Scope:        "user:inference",
	}
	if err := store.Save("anthropic", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := m.Status("anthropic")
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil token from Status")
	}
	// Status must NOT trigger refresh — returns original token
	if got.AccessToken != "status-access" {
		t.Errorf("expected status-access, got %q", got.AccessToken)
	}
}

func TestManager_Logout_RemovesToken(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	tok := OAuthToken{
		AccessToken: "to-be-removed",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := store.Save("anthropic", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := m.Logout("anthropic"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	got, err := store.Load("anthropic")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after logout, got %+v", got)
	}
}

func TestProvider_AuthorizationURL(t *testing.T) {
	cfg := config.OAuthProviderConfig{
		Name:        "anthropic",
		ClientID:    "my-client-id",
		AuthURL:     "https://auth.example.com/oauth/authorize",
		TokenURL:    "https://auth.example.com/oauth/token",
		RedirectURI: "http://localhost:8080/callback",
		Scopes:      []string{"user:inference", "org:read"},
	}
	p := NewAnthropicProvider(cfg)

	state := "test-state-value"
	challenge := "test-challenge-value"
	rawURL := p.AuthorizationURL(state, challenge)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := parsed.Query()

	checks := map[string]string{
		"client_id":             "my-client-id",
		"redirect_uri":          "http://localhost:8080/callback",
		"response_type":         "code",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
		"state":                 state,
	}
	for key, want := range checks {
		if got := q.Get(key); got != want {
			t.Errorf("param %q: got %q, want %q", key, got, want)
		}
	}

	scope := q.Get("scope")
	if !strings.Contains(scope, "user:inference") || !strings.Contains(scope, "org:read") {
		t.Errorf("scope %q missing expected values", scope)
	}
}
