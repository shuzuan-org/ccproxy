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
	tracker := loadbalancer.NewConcurrencyTracker()
	instances := []config.InstanceConfig{
		{Name: "test-oauth", AuthMode: "oauth", MaxConcurrency: 5},
	}
	balancer := loadbalancer.NewBalancer(instances, tracker)
	store, err := oauth.NewTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	mgr := oauth.NewManager(instances, store)
	sessions := oauth.NewSessionStore()
	cfg := &config.Config{
		Instances: instances,
	}
	return NewHandler(balancer, mgr, sessions, cfg)
}

func TestHandleInstances_IncludesTokenStatus(t *testing.T) {
	h := newTestHandler(t)

	tok := oauth.OAuthToken{
		AccessToken: "test",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := h.oauthMgr.GetStore().Save("test-oauth", tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/instances", nil)
	w := httptest.NewRecorder()
	h.HandleInstances(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var states []InstanceState
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

func TestHandleInstances_NoToken(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest("GET", "/api/instances", nil)
	w := httptest.NewRecorder()
	h.HandleInstances(w, req)

	var states []InstanceState
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

	body, _ := json.Marshal(map[string]string{"instance": "test-oauth"})
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

func TestHandleOAuthLoginStart_InvalidInstance(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"instance": "nonexistent"})
	req := httptest.NewRequest("POST", "/api/oauth/login/start", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginStart(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleOAuthRefresh_NoToken(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"instance": "test-oauth"})
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

	body, _ := json.Marshal(map[string]string{"instance": "test-oauth"})
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
