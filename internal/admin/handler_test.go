package admin

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()

	dir := t.TempDir()
	registry := config.NewAccountRegistry(dir)
	_ = registry.Add("test-oauth")

	cfg := &config.Config{
		Server: config.ServerConfig{
			BaseURL:        "https://api.anthropic.com",
			RequestTimeout: 300,
			MaxConcurrency: 5,
		},
	}
	runtimeAccounts := cfg.RuntimeAccounts(registry)

	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer(runtimeAccounts, tracker)
	store, err := oauth.NewTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	mgr := oauth.NewManager(registry.Names(), store, nil)
	sessions := oauth.NewSessionStore()
	return NewHandler(balancer, mgr, sessions, cfg, registry)
}

func TestHandleAccounts_IncludesTokenStatus(t *testing.T) {
	h := newTestHandler(t)

	tok := oauth.OAuthToken{
		AccessToken: "test",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := h.oauthMgr.GetStore().Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/accounts", nil)
	w := httptest.NewRecorder()
	h.HandleAccounts(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var states []AccountState
	if err := json.NewDecoder(w.Body).Decode(&states); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("len = %d, want 1", len(states))
	}
	if states[0].TokenStatus != "valid" {
		t.Errorf("token_status = %q, want valid", states[0].TokenStatus)
	}
}

func TestHandleAccounts_NoToken(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest("GET", "/api/accounts", nil)
	w := httptest.NewRecorder()
	h.HandleAccounts(w, req)

	var states []AccountState
	if err := json.NewDecoder(w.Body).Decode(&states); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if len(states) != 1 {
		t.Fatalf("len = %d, want 1", len(states))
	}
	if states[0].TokenStatus != "no token" {
		t.Errorf("token_status = %q, want 'no token'", states[0].TokenStatus)
	}
}

func TestHandleOAuthLoginStart(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"account": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/oauth/login/start", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginStart(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["session_id"] == "" {
		t.Error("missing session_id")
	}
	if resp["authorization_url"] == "" {
		t.Error("missing authorization_url")
	}
}

func TestHandleOAuthLoginStart_InvalidAccount(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"account": "nonexistent"})
	req := httptest.NewRequest("POST", "/api/oauth/login/start", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginStart(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleOAuthRefresh_NoToken(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"account": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/oauth/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthRefresh(w, req)

	if w.Code == 200 {
		t.Error("expected error when no token stored")
	}
}

func TestHandleOAuthLogout(t *testing.T) {
	h := newTestHandler(t)

	tok := oauth.OAuthToken{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)}
	if err := h.oauthMgr.GetStore().Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"account": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/oauth/logout", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLogout(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}

	got, _ := h.oauthMgr.GetStore().Load("test-oauth")
	if got != nil {
		t.Error("token should be deleted after logout")
	}
}

func TestHandleAddAccount(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "new-account"})
	req := httptest.NewRequest("POST", "/api/accounts/add", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAddAccount(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify it shows up in the list
	if !h.registry.Has("new-account") {
		t.Error("new-account not found in registry")
	}
}

func TestHandleAddAccount_Duplicate(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/accounts/add", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleAddAccount(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400 for duplicate", w.Code)
	}
}

func TestHandleRemoveAccount(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/accounts/remove", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleRemoveAccount(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	if h.registry.Has("test-oauth") {
		t.Error("test-oauth should have been removed")
	}
}
