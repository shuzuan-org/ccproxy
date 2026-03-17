package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	return NewHandler(balancer, mgr, sessions, cfg, registry, nil)
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

func TestHandleRemoveAccount_NotFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "does-not-exist"})
	req := httptest.NewRequest("POST", "/api/accounts/remove", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleRemoveAccount(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleUpdateProxy(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "test-oauth", "proxy": "socks5://127.0.0.1:1080"})
	req := httptest.NewRequest("POST", "/api/accounts/proxy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleUpdateProxy(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	got := h.registry.GetProxy("test-oauth")
	if got != "socks5://127.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://127.0.0.1:1080", got)
	}
}

func TestHandleUpdateProxy_NotFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "nonexistent", "proxy": "socks5://127.0.0.1:1080"})
	req := httptest.NewRequest("POST", "/api/accounts/proxy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleUpdateProxy(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleSessions(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	h.HandleSessions(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleDashboard(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	handler := h.HandleDashboard()
	req := httptest.NewRequest("GET", "/index.html", nil)
	w := httptest.NewRecorder()

	// Should not panic; static files are embedded at build time.
	handler.ServeHTTP(w, req)
	// We only verify it doesn't panic and returns a response.
	if w.Code == 0 {
		t.Error("expected a non-zero status code")
	}
}

func TestHandleOAuthLoginComplete_PassesFullCodeWithState(t *testing.T) {
	// CRITICAL regression test: the handler MUST pass the full code (including #state)
	// to ExchangeAndSave, so the provider can extract and send the state parameter
	// to Anthropic's token endpoint. Anthropic rejects requests without state.
	// Regression: commit 849d241 stripped state in handler, breaking OAuth login.

	// Create a mock token server that captures the request body.
	var receivedBody map[string]any
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "test-access",
			"refresh_token": "test-refresh",
			"expires_in":    3600,
			"scope":         "user:inference",
		})
	}))
	defer tokenSrv.Close()

	// Build handler with provider pointing to mock server.
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
	store, _ := oauth.NewTokenStore(t.TempDir())
	mgr := oauth.NewManager(registry.Names(), store, nil)
	mgr.GetProvider().SetTokenURL(tokenSrv.URL)
	sessions := oauth.NewSessionStore()
	h := NewHandler(balancer, mgr, sessions, cfg, registry, nil)

	// Start a PKCE session to get a valid session ID and state.
	sessionID, _, err := sessions.Create("test-oauth")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	session, _ := sessions.Get(sessionID)
	state := session.State

	// Submit code with correct state appended after '#'.
	fullCode := "TpDo2YA9RPCH1jeIUF96XAqcH6BxEytjyIVtsVWhhOL9YooD#" + state
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"code":       fullCode,
	})
	req := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify the state was sent to Anthropic's token endpoint.
	if receivedBody["state"] != state {
		t.Errorf("token request state = %v, want %q — handler must pass full code to provider", receivedBody["state"], state)
	}
	// Verify only the auth code (without #state) was sent as the code parameter.
	if code, _ := receivedBody["code"].(string); code != "TpDo2YA9RPCH1jeIUF96XAqcH6BxEytjyIVtsVWhhOL9YooD" {
		t.Errorf("token request code = %q, want auth code without #state suffix", code)
	}
}

func TestHandleOAuthLoginComplete_SessionPreservedOnExchangeFailure(t *testing.T) {
	// When token exchange fails, the session MUST be preserved so the user
	// can retry without starting a new login flow.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenSrv.Close()

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
	store, _ := oauth.NewTokenStore(t.TempDir())
	mgr := oauth.NewManager(registry.Names(), store, nil)
	mgr.GetProvider().SetTokenURL(tokenSrv.URL)
	sessions := oauth.NewSessionStore()
	h := NewHandler(balancer, mgr, sessions, cfg, registry, nil)

	sessionID, _, _ := sessions.Create("test-oauth")
	session, _ := sessions.Get(sessionID)

	fullCode := "somecode#" + session.State
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"code":       fullCode,
	})
	req := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(w, req)

	if w.Code == 200 {
		t.Fatal("expected error response for failed exchange")
	}

	// Session must still exist for retry.
	if _, ok := sessions.Get(sessionID); !ok {
		t.Error("session was deleted after exchange failure — user cannot retry")
	}
}

func TestHandleOAuthLoginComplete_ErrorResponseIsNotHTTP5xx(t *testing.T) {
	// Admin API error responses MUST NOT use 5xx status codes, because
	// Cloudflare replaces 502/503 responses with its own HTML error pages,
	// breaking the frontend JSON parser.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenSrv.Close()

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
	store, _ := oauth.NewTokenStore(t.TempDir())
	mgr := oauth.NewManager(registry.Names(), store, nil)
	mgr.GetProvider().SetTokenURL(tokenSrv.URL)
	sessions := oauth.NewSessionStore()
	h := NewHandler(balancer, mgr, sessions, cfg, registry, nil)

	sessionID, _, _ := sessions.Create("test-oauth")
	session, _ := sessions.Get(sessionID)

	fullCode := "somecode#" + session.State
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"code":       fullCode,
	})
	req := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(w, req)

	if w.Code >= 500 {
		t.Errorf("status = %d — admin API must not return 5xx (Cloudflare replaces with HTML)", w.Code)
	}

	// Verify it returns JSON, not HTML.
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleOAuthLoginComplete_InvalidSession(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{
		"session_id": "nonexistent-session-id",
		"code":       "somecode",
	})
	req := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleOAuthLoginComplete_StateMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)

	// Start a real PKCE session.
	sessionID, _, err := h.sessions.Create("test-oauth")
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}

	// Verify session exists before the request.
	if _, ok := h.sessions.Get(sessionID); !ok {
		t.Fatal("session should exist before complete attempt")
	}

	// Submit with wrong state (code does not contain the correct state after '#').
	body, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"code":       "authcode#wrong-state-value",
	})
	req := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400 (CSRF protection)", w.Code)
	}

	// Session must be deleted after state mismatch (CSRF protection).
	if _, ok := h.sessions.Get(sessionID); ok {
		t.Error("session should have been deleted after state mismatch")
	}
}

func TestTokenStatus(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		token *oauth.OAuthToken
		want  string
	}{
		{"nil token", nil, "no token"},
		{"expired", &oauth.OAuthToken{ExpiresAt: time.Now().Add(-time.Hour)}, "expired"},
		{"expiring soon", &oauth.OAuthToken{ExpiresAt: time.Now().Add(2 * time.Minute)}, "expiring soon"},
		{"valid", &oauth.OAuthToken{ExpiresAt: time.Now().Add(time.Hour)}, "valid"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tokenStatus(tc.token)
			if got != tc.want {
				t.Errorf("tokenStatus() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	writeJSON(w, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	body := w.Body.String()
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("body does not end with newline: %q", body)
	}
}

func TestWriteError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "something went wrong")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] != "something went wrong" {
		t.Errorf("error = %q, want 'something went wrong'", resp["error"])
	}
}

func TestDecodeBody_InvalidJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", strings.NewReader("{invalid json"))
	var v map[string]string
	ok := decodeBody(w, req, &v)

	if ok {
		t.Error("decodeBody should return false for invalid JSON")
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
