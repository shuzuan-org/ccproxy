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
)

// newTestManager creates a Manager backed by a temp TokenStore and pointing to
// the given token server URL.
func newTestManager(t *testing.T, tokenServerURL string) (*Manager, *TokenStore) {
	t.Helper()
	store, err := NewTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	m := NewManager([]string{"test-oauth"}, store, nil)
	// Override provider's tokenURL for testing
	m.provider.tokenURL = tokenServerURL
	return m, store
}

// mockTokenServer returns an httptest.Server that responds with a token JSON.
func mockTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
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
	if err := store.Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := m.GetValidToken(context.Background(), "test-oauth")
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
	if err := store.Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := m.GetValidToken(context.Background(), "test-oauth")
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

	_, err := m.GetValidToken(context.Background(), "test-oauth")
	if err == nil {
		t.Fatal("expected error when no token stored")
	}
	if !strings.Contains(err.Error(), "no token for account") {
		t.Errorf("expected account hint in error, got: %v", err)
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
	if err := store.Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := m.Status("test-oauth")
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
	if err := store.Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := m.Logout("test-oauth"); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	got, err := store.Load("test-oauth")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after logout, got %+v", got)
	}
}

func TestProvider_AuthorizationURL(t *testing.T) {
	p := NewAnthropicProvider()

	state := "test-state-value"
	challenge := "test-challenge-value"
	rawURL := p.AuthorizationURL(state, challenge)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := parsed.Query()

	checks := map[string]string{
		"client_id":             ClientID,
		"redirect_uri":          RedirectURI,
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
	if !strings.Contains(scope, "user:inference") {
		t.Errorf("scope %q missing user:inference", scope)
	}
}

func TestExchangeCode_Success(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	token, err := m.GetProvider().ExchangeCode(context.Background(), "auth-code", "verifier", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}
	if token.RefreshToken != "new-refresh" {
		t.Errorf("refresh_token = %q, want new-refresh", token.RefreshToken)
	}
}

func TestExchangeCode_WithState(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	token, err := m.GetProvider().ExchangeCode(context.Background(), "auth-code#mystate", "verifier", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}
}

func TestExchangeCode_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.GetProvider().ExchangeCode(context.Background(), "bad-code", "verifier", "")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Errorf("error = %q, want 'status 400'", err.Error())
	}
}

func TestRefreshToken_Success(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	token, err := m.GetProvider().RefreshToken(context.Background(), "old-refresh", "")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}
}

func TestRefreshToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.GetProvider().RefreshToken(context.Background(), "bad-refresh", "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetProxyClient_Caching(t *testing.T) {
	p := NewAnthropicProvider()

	c1 := p.getProxyClient("socks5://127.0.0.1:19999")
	c2 := p.getProxyClient("socks5://127.0.0.1:19999")
	if c1 != c2 {
		t.Error("expected same cached client for same proxyURL")
	}

	c3 := p.getProxyClient("socks5://127.0.0.1:29999")
	if c1 == c3 {
		t.Error("expected different client for different proxyURL")
	}
}

func TestUpdateAccounts_AddNew(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	m.UpdateAccounts([]string{"test-oauth", "new-account"})

	_, err := m.GetValidToken(context.Background(), "new-account")
	if err == nil {
		t.Fatal("expected error for account with no token")
	}
	if !strings.Contains(err.Error(), "no token") {
		t.Errorf("error = %q, want 'no token' hint", err.Error())
	}
}

func TestUpdateAccounts_MutexNotCleaned(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	m.UpdateAccounts([]string{"test-oauth", "extra"})
	m.UpdateAccounts([]string{"test-oauth"})

	m.mu.RLock()
	_, exists := m.refreshMu["extra"]
	m.mu.RUnlock()
	if !exists {
		t.Error("mutex for removed account should still exist (known limitation)")
	}
}

func TestExchangeAndSave(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	token, err := m.ExchangeAndSave(context.Background(), "test-oauth", "auth-code", "verifier", "")
	if err != nil {
		t.Fatalf("ExchangeAndSave: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}

	loaded, err := store.Load("test-oauth")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected persisted token")
	}
	if loaded.AccessToken != "new-access" {
		t.Errorf("persisted access_token = %q, want new-access", loaded.AccessToken)
	}
}

func TestForceRefresh(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	tok := OAuthToken{
		AccessToken:  "old",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = store.Save("test-oauth", tok)

	newToken, err := m.ForceRefresh(context.Background(), "test-oauth")
	if err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if newToken.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", newToken.AccessToken)
	}
}

func TestForceRefresh_NoToken(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.ForceRefresh(context.Background(), "test-oauth")
	if err == nil {
		t.Fatal("expected error when no token stored")
	}
}

func TestMarkTokenExpired(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	tok := OAuthToken{
		AccessToken:  "still-valid",
		RefreshToken: "refresh-me",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = store.Save("test-oauth", tok)

	m.MarkTokenExpired("test-oauth")

	loaded, _ := store.Load("test-oauth")
	if loaded == nil {
		t.Fatal("expected token to still exist")
	}
	if time.Until(loaded.ExpiresAt) > time.Second {
		t.Errorf("token should be expired, expires_at = %v", loaded.ExpiresAt)
	}
}

func TestGetValidToken_ConcurrentRefresh(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	tok := OAuthToken{
		AccessToken:  "expiring",
		RefreshToken: "refresh-me",
		ExpiresAt:    time.Now().Add(30 * time.Second),
	}
	_ = store.Save("test-oauth", tok)

	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := m.GetValidToken(context.Background(), "test-oauth")
			errs <- err
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}
