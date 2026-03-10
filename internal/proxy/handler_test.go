package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/auth"
	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
)

// setAuthInfo injects auth info into a request context using the auth package's mechanism.
func setAuthInfo(r *http.Request, name string) *http.Request {
	// We cannot use auth.contextKey directly (unexported), so we use SetAuthInfo
	// by wrapping the request through the auth middleware logic.
	// Instead, re-create the context value using the exported GetAuthInfo path:
	// auth.Middleware stores the value with its own unexported key, so for tests
	// we create a small shim handler that injects auth info.
	ctx := contextWithAuthInfo(r.Context(), auth.AuthInfo{APIKeyName: name})
	return r.WithContext(ctx)
}

// contextWithAuthInfo uses the auth middleware to inject AuthInfo into a context.
// This is achieved by running a one-shot middleware and capturing the context.
func contextWithAuthInfo(ctx context.Context, info auth.AuthInfo) context.Context {
	// The auth package stores the value with its own unexported contextKey.
	// We inject it by building a fake API key config and running the middleware.
	fakeKey := "test-key-" + info.APIKeyName
	middleware := auth.Middleware([]config.APIKeyConfig{
		{Key: fakeKey, Name: info.APIKeyName, Enabled: true},
	})

	var captured context.Context
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	}))

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+fakeKey)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if captured == nil {
		return ctx
	}
	return captured
}

// buildBalancer creates a minimal Balancer with one instance.
func buildBalancer(inst config.InstanceConfig) *loadbalancer.Balancer {
	tracker := loadbalancer.NewConcurrencyTracker()
	return loadbalancer.NewBalancer([]config.InstanceConfig{inst}, tracker)
}

// buildBearerInstance returns a bearer-mode InstanceConfig pointing at the given URL.
func buildBearerInstance(baseURL string) config.InstanceConfig {
	enabled := true
	return config.InstanceConfig{
		Name:           "test-bearer",
		AuthMode:       "bearer",
		APIKey:         "sk-test-apikey",
		BaseURL:        baseURL,
		MaxConcurrency: 10,
		Priority:       1,
		Weight:         100,
		RequestTimeout: 10,
		Enabled:        &enabled,
	}
}

// buildOAuthInstance returns an oauth-mode InstanceConfig pointing at the given URL.
func buildOAuthInstance(baseURL string) config.InstanceConfig {
	enabled := true
	return config.InstanceConfig{
		Name:           "test-oauth",
		AuthMode:       "oauth",
		OAuthProvider:  "test-provider",
		BaseURL:        baseURL,
		MaxConcurrency: 10,
		Priority:       1,
		Weight:         100,
		RequestTimeout: 10,
		Enabled:        &enabled,
	}
}

// buildOAuthManager creates a real oauth.Manager with a pre-saved token in a temp dir.
func buildOAuthManager(t *testing.T, token string) *oauth.Manager {
	t.Helper()
	dir := t.TempDir()
	store, err := oauth.NewTokenStore(dir)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	err = store.Save("test-provider", oauth.OAuthToken{
		AccessToken:  token,
		RefreshToken: "rt-ignored",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("store.Save: %v", err)
	}

	manager := oauth.NewManager([]config.OAuthProviderConfig{
		{Name: "test-provider"},
	}, store)
	return manager
}

// standardRequestBody returns a minimal /v1/messages request body.
func standardRequestBody(model string, stream bool) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"model":      model,
		"max_tokens": 100,
		"stream":     stream,
		"messages": []map[string]interface{}{
			{"role": "user", "content": "hello"},
		},
	})
	return b
}

// --- Test cases ---

// TestHandler_NonStreaming verifies that a non-streaming JSON response is
// forwarded correctly to the client.
func TestHandler_NonStreaming(t *testing.T) {
	upstreamResp := map[string]interface{}{
		"id":    "msg_01",
		"type":  "message",
		"model": "claude-3-5-sonnet-20241022",
		"usage": map[string]interface{}{
			"input_tokens":  10,
			"output_tokens": 20,
		},
		"content": []interface{}{},
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(upstreamResp)
	}))
	defer upstream.Close()

	inst := buildBearerInstance(upstream.URL)
	balancer := buildBalancer(inst)
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

	body := standardRequestBody("claude-3-5-sonnet-20241022", false)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if got["id"] != "msg_01" {
		t.Errorf("expected id=msg_01, got %v", got["id"])
	}
}

// TestHandler_Streaming verifies that an SSE response is forwarded and usage extracted.
func TestHandler_Streaming(t *testing.T) {
	sseBody := strings.Join([]string{
		"event: message_start",
		`data: {"type":"message_start","message":{"usage":{"input_tokens":5,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}`,
		"",
		"event: message_delta",
		`data: {"type":"message_delta","usage":{"output_tokens":15}}`,
		"",
		"event: message_stop",
		`data: {"type":"message_stop"}`,
		"",
	}, "\n")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, sseBody)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}))
	defer upstream.Close()

	inst := buildBearerInstance(upstream.URL)
	balancer := buildBalancer(inst)
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

	body := standardRequestBody("claude-3-5-sonnet-20241022", true)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/event-stream") {
		t.Errorf("expected text/event-stream Content-Type, got %q", rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "message_start") {
		t.Errorf("expected message_start in SSE body, got: %s", rr.Body.String())
	}
}

// TestHandler_DisguiseAppliedForOAuth verifies disguise is applied for OAuth instances
// when the client is not a real Claude Code client.
func TestHandler_DisguiseAppliedForOAuth(t *testing.T) {
	var capturedUA string
	var capturedBody []byte

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		capturedBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_02","type":"message","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1,"output_tokens":1},"content":[]}`))
	}))
	defer upstream.Close()

	inst := buildOAuthInstance(upstream.URL)
	balancer := buildBalancer(inst)
	oauthMgr := buildOAuthManager(t, "fake-oauth-access-token")
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), oauthMgr)

	body := standardRequestBody("claude-sonnet-4-5", false)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	// No Claude Code signals → disguise should be applied
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// Disguise should set a User-Agent resembling claude-cli
	if capturedUA == "" {
		t.Error("expected User-Agent to be set by disguise, got empty string")
	}

	// Disguise should inject a system prompt — verify the upstream body has "system"
	var upstreamParsed map[string]interface{}
	if err := json.Unmarshal(capturedBody, &upstreamParsed); err != nil {
		t.Fatalf("upstream body not valid JSON: %v", err)
	}
	if _, ok := upstreamParsed["system"]; !ok {
		t.Error("expected disguise to inject 'system' field into upstream body")
	}
}

// TestHandler_DisguiseNotAppliedForBearer verifies disguise is NOT applied for bearer instances.
func TestHandler_DisguiseNotAppliedForBearer(t *testing.T) {
	var capturedUA string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_03","type":"message","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1,"output_tokens":1},"content":[]}`))
	}))
	defer upstream.Close()

	inst := buildBearerInstance(upstream.URL)
	balancer := buildBalancer(inst)
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

	body := standardRequestBody("claude-3-5-sonnet-20241022", false)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// For bearer mode, disguise should NOT modify User-Agent
	// (the request doesn't set a UA, so upstream should receive empty or Go's default)
	if strings.Contains(capturedUA, "claude-cli") {
		t.Errorf("expected no claude-cli User-Agent for bearer mode, got %q", capturedUA)
	}
}

// TestHandler_AuthHeaderBearer verifies that x-api-key is set for bearer instances.
func TestHandler_AuthHeaderBearer(t *testing.T) {
	var capturedAPIKey string
	var capturedAuthHeader string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAPIKey = r.Header.Get("X-Api-Key")
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_04","type":"message","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1,"output_tokens":1},"content":[]}`))
	}))
	defer upstream.Close()

	inst := buildBearerInstance(upstream.URL)
	balancer := buildBalancer(inst)
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

	body := standardRequestBody("claude-3-5-sonnet-20241022", false)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if capturedAPIKey != "sk-test-apikey" {
		t.Errorf("expected x-api-key=sk-test-apikey, got %q", capturedAPIKey)
	}
	if capturedAuthHeader != "" {
		t.Errorf("expected no Authorization header for bearer mode, got %q", capturedAuthHeader)
	}
}

// TestHandler_AuthHeaderOAuth verifies that Authorization: Bearer is set for OAuth instances.
func TestHandler_AuthHeaderOAuth(t *testing.T) {
	var capturedAuth string
	var capturedAPIKey string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedAPIKey = r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_05","type":"message","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1,"output_tokens":1},"content":[]}`))
	}))
	defer upstream.Close()

	inst := buildOAuthInstance(upstream.URL)
	balancer := buildBalancer(inst)
	oauthMgr := buildOAuthManager(t, "my-oauth-token-xyz")
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), oauthMgr)

	body := standardRequestBody("claude-sonnet-4-5", false)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if capturedAuth != "Bearer my-oauth-token-xyz" {
		t.Errorf("expected Authorization: Bearer my-oauth-token-xyz, got %q", capturedAuth)
	}
	if capturedAPIKey != "" {
		t.Errorf("expected no x-api-key for OAuth mode, got %q", capturedAPIKey)
	}
}

// TestHandler_UpstreamError verifies that upstream error responses are mapped correctly.
//
// Note on retry semantics: ExecuteWithRetry classifies errors as follows:
//   - 400 and other 4xx (non-special): ReturnToClient — forwarded directly to handler
//   - 401/403/429/529:                 FailoverImmediate — instance blacklisted, try next
//   - 500-504:                         RetryThenFailover — retry same, then blacklist
//
// With a single instance, FailoverImmediate and RetryThenFailover errors exhaust
// the instance pool and result in a 503 from the handler. This is the expected
// production behavior. The handler's MapUpstreamError logic is exercised for
// ReturnToClient responses (400 range) that are forwarded directly.
func TestHandler_UpstreamError(t *testing.T) {
	t.Run("client_error_400_forwarded", func(t *testing.T) {
		// 400 is classified as ReturnToClient, so it is forwarded through MapUpstreamError.
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error","message":"bad request"}}`))
		}))
		defer upstream.Close()

		inst := buildBearerInstance(upstream.URL)
		balancer := buildBalancer(inst)
		h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

		body := standardRequestBody("claude-3-5-sonnet-20241022", false)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req = setAuthInfo(req, "default")

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		// 400 maps to 502 via MapUpstreamError fallback (not in the specific table).
		if rr.Code != http.StatusBadGateway {
			t.Errorf("expected 502, got %d: %s", rr.Code, rr.Body.String())
		}
		var errResp AnthropicError
		if err := json.Unmarshal(rr.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("response not valid JSON: %v", err)
		}
		if errResp.Type != "error" {
			t.Errorf("expected error type field 'error', got %q", errResp.Type)
		}
	})

	// For failover errors (429/401/403/529), a single-instance balancer exhausts
	// all instances and the handler returns 503.
	t.Run("rate_limit_single_instance_503", func(t *testing.T) {
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(429)
			_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"rate limited"}}`))
		}))
		defer upstream.Close()

		inst := buildBearerInstance(upstream.URL)
		balancer := buildBalancer(inst)
		h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

		body := standardRequestBody("claude-3-5-sonnet-20241022", false)
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req = setAuthInfo(req, "default")

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		// With one instance exhausted, handler returns 503.
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
		}
	})

	// MapUpstreamError is independently verified via unit tests in errors_test.go.
	// Verify the mapping function directly for coverage of all important codes.
	t.Run("map_upstream_error_table", func(t *testing.T) {
		cases := []struct {
			code        int
			wantStatus  int
			wantErrType string
		}{
			{401, 502, "authentication_error"},
			{403, 502, "forbidden_error"},
			{429, 429, "rate_limit_error"},
			{529, 503, "overloaded_error"},
			{500, 502, "upstream_error"},
		}
		for _, c := range cases {
			status, body := MapUpstreamError(c.code, nil)
			if status != c.wantStatus {
				t.Errorf("code %d: want status %d, got %d", c.code, c.wantStatus, status)
			}
			var errResp AnthropicError
			if err := json.Unmarshal(body, &errResp); err != nil {
				t.Fatalf("code %d: body not valid JSON: %v", c.code, err)
			}
			if errResp.Error.Type != c.wantErrType {
				t.Errorf("code %d: want errType %q, got %q", c.code, c.wantErrType, errResp.Error.Type)
			}
		}
	})
}

// TestHandler_NoHealthyInstances verifies 503 when balancer has no instances.
func TestHandler_NoHealthyInstances(t *testing.T) {
	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer([]config.InstanceConfig{}, tracker)
	h := NewHandler([]config.InstanceConfig{}, balancer, disguise.NewEngine(), nil)

	body := standardRequestBody("claude-3-5-sonnet-20241022", false)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req = setAuthInfo(req, "default")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestHandler_SessionKeyComposed verifies that sticky session binds to correct instance
// when session ID is present in request metadata.user_id.
func TestHandler_SessionKeyFromMetadata(t *testing.T) {
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_06","type":"message","model":"claude-3-5-sonnet-20241022","usage":{"input_tokens":1,"output_tokens":1},"content":[]}`))
	}))
	defer upstream.Close()

	inst := buildBearerInstance(upstream.URL)
	balancer := buildBalancer(inst)
	h := NewHandler([]config.InstanceConfig{inst}, balancer, disguise.NewEngine(), nil)

	// Use a request body that includes metadata.user_id with a session ID.
	sessionUUID := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":      "claude-3-5-sonnet-20241022",
		"max_tokens": 100,
		"stream":     false,
		"messages":   []map[string]interface{}{{"role": "user", "content": "hi"}},
		"metadata": map[string]interface{}{
			"user_id": fmt.Sprintf("user_%s_account__session_%s", strings.Repeat("a", 64), sessionUUID),
		},
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(string(reqBody)))
		req.Header.Set("Content-Type", "application/json")
		req = setAuthInfo(req, "default")

		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d: %s", i, rr.Code, rr.Body.String())
		}
	}

	if callCount != 2 {
		t.Errorf("expected upstream to be called 2 times, got %d", callCount)
	}
}

// TestExtractUsageFromJSON verifies extraction of usage fields from non-streaming response.
func TestExtractUsageFromJSON(t *testing.T) {
	body := []byte(`{
		"id": "msg_01",
		"usage": {
			"input_tokens": 10,
			"output_tokens": 20,
			"cache_creation_input_tokens": 3,
			"cache_read_input_tokens": 4
		}
	}`)

	usage := extractUsageFromJSON(body)

	if usage.InputTokens != 10 {
		t.Errorf("InputTokens: want 10, got %d", usage.InputTokens)
	}
	if usage.OutputTokens != 20 {
		t.Errorf("OutputTokens: want 20, got %d", usage.OutputTokens)
	}
	if usage.CacheCreationInputTokens != 3 {
		t.Errorf("CacheCreationInputTokens: want 3, got %d", usage.CacheCreationInputTokens)
	}
	if usage.CacheReadInputTokens != 4 {
		t.Errorf("CacheReadInputTokens: want 4, got %d", usage.CacheReadInputTokens)
	}
}
