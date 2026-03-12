package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/auth"
	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/binn/ccproxy/internal/proxy"
)

// mockServer wraps the upstream Anthropic mock and records the requests it received.
type mockServer struct {
	srv             *httptest.Server
	mu              sync.Mutex
	receivedHeaders []http.Header
	// mode controls what response to serve:
	//   "ok"       → normal 200 JSON response
	//   "stream"   → SSE streaming response
	//   "error503" → returns HTTP 503
	mode string
}

func newMockAnthropicServer(t *testing.T, mode string) *mockServer {
	t.Helper()
	ms := &mockServer{mode: mode}
	ms.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only handle the messages endpoint.
		if r.URL.Path != "/v1/messages" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}

		// Record headers for assertion in tests.
		ms.mu.Lock()
		hdrs := r.Header.Clone()
		ms.receivedHeaders = append(ms.receivedHeaders, hdrs)
		ms.mu.Unlock()

		switch ms.mode {
		case "stream":
			serveSSE(w)
		case "error503":
			http.Error(w, `{"type":"error","error":{"type":"overloaded_error","message":"overloaded"}}`, http.StatusServiceUnavailable)
		default: // "ok"
			serveJSON(w)
		}
	}))
	t.Cleanup(ms.srv.Close)
	return ms
}

func serveJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{
		"id": "msg_test123",
		"type": "message",
		"role": "assistant",
		"content": [{"type": "text", "text": "Hello!"}],
		"model": "claude-sonnet-4-5-20250929",
		"usage": {"input_tokens": 10, "output_tokens": 5}
	}`))
}

func serveSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	events := []string{
		`event: message_start
data: {"type":"message_start","message":{"id":"msg_test123","type":"message","role":"assistant","model":"claude-sonnet-4-5-20250929","usage":{"input_tokens":10,"cache_creation_input_tokens":0,"cache_read_input_tokens":0}}}

`,
		`event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

`,
		`event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello!"}}

`,
		`event: content_block_stop
data: {"type":"content_block_stop","index":0}

`,
		`event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":5}}

`,
		`event: message_stop
data: {"type":"message_stop"}

`,
	}
	for _, ev := range events {
		_, _ = fmt.Fprint(w, ev)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// ---------------------------------------------------------------------------
// Helper: build a minimal ccproxy HTTP handler stack.
// ---------------------------------------------------------------------------

const (
	testAPIKey     = "test-key-integration"
	testAPIKeyName = "integration-test-key"
)

// buildHandler constructs the proxy mux the same way server.New() does.
func buildHandler(t *testing.T, cfg *config.Config, instances []config.InstanceConfig) http.Handler {
	t.Helper()

	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer(instances, tracker)

	disguiseEngine := disguise.NewEngine()

	// Create OAuth manager with pre-saved tokens for all instances.
	oauthMgr := buildIntegrationOAuthManager(t, instances)
	proxyHandler := proxy.NewHandler(cfg.Server.BaseURL, cfg.Server.RequestTimeout, balancer, disguiseEngine, oauthMgr)

	mux := http.NewServeMux()
	mux.Handle("/v1/messages", auth.Middleware(cfg.APIKeys)(http.HandlerFunc(proxyHandler.ServeHTTP)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// startProxyServer starts a real TCP listener for the given handler and returns its URL.
// The server is stopped via t.Cleanup.
func startProxyServer(t *testing.T, handler http.Handler) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() { _ = srv.Serve(ln) }()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	})

	return "http://" + ln.Addr().String()
}

// makeConfig returns a minimal valid Config pointing upstream requests at upstreamURL.
// Also returns the runtime InstanceConfig list (since instances are no longer in Config).
func makeConfig(upstreamURL string) (*config.Config, []config.InstanceConfig) {
	enabled := true
	cfg := &config.Config{
		Server: config.ServerConfig{
			Host:           "127.0.0.1",
			Port:           0,
			BaseURL:        upstreamURL,
			RequestTimeout: 10,
			MaxConcurrency: 5,
		},
		APIKeys: []config.APIKeyConfig{
			{Key: testAPIKey, Name: testAPIKeyName, Enabled: true},
		},
	}
	instances := []config.InstanceConfig{
		{
			Name:           "test-instance",
			BaseURL:        upstreamURL,
			MaxConcurrency: 5,
			RequestTimeout: 10,
			Enabled:        &enabled,
		},
	}
	return cfg, instances
}

// buildIntegrationOAuthManager creates an oauth.Manager with pre-saved tokens for all instances.
func buildIntegrationOAuthManager(t *testing.T, instances []config.InstanceConfig) *oauth.Manager {
	t.Helper()
	dir := t.TempDir()
	store, err := oauth.NewTokenStore(dir)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	names := make([]string, len(instances))
	for i, inst := range instances {
		names[i] = inst.Name
		err = store.Save(inst.Name, oauth.OAuthToken{
			AccessToken:  "fake-integration-token",
			RefreshToken: "rt-ignored",
			ExpiresAt:    time.Now().Add(1 * time.Hour),
		})
		if err != nil {
			t.Fatalf("store.Save(%q): %v", inst.Name, err)
		}
	}
	return oauth.NewManager(names, store, nil)
}

// postMessages sends a POST /v1/messages to proxyURL with optional auth token
// and request body. Returns the raw *http.Response.
func postMessages(t *testing.T, proxyURL, authToken string, body interface{}) *http.Response {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(http.MethodPost, proxyURL+"/v1/messages", bodyReader)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// standardRequestBody returns a minimal non-streaming messages request body.
func standardRequestBody() map[string]interface{} {
	return map[string]interface{}{
		"model":      "claude-3-5-haiku-20241022",
		"max_tokens": 1024,
		"messages": []map[string]interface{}{
			{"role": "user", "content": "Hello"},
		},
	}
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

// TestIntegration_AuthRequired verifies that a request without an auth token
// is rejected with HTTP 401.
func TestIntegration_AuthRequired(t *testing.T) {
	upstream := newMockAnthropicServer(t, "ok")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	resp := postMessages(t, proxyURL, "" /* no token */, standardRequestBody())
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}

	var errResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if errResp["type"] != "error" {
		t.Errorf("expected error type 'error', got %v", errResp["type"])
	}
}

// TestIntegration_InvalidAuth verifies that a request with a wrong bearer
// token is rejected with HTTP 401.
func TestIntegration_InvalidAuth(t *testing.T) {
	upstream := newMockAnthropicServer(t, "ok")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	resp := postMessages(t, proxyURL, "wrong-token", standardRequestBody())
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", resp.StatusCode)
	}
}

// TestIntegration_NonStreamingRequest verifies that a valid non-streaming
// request is forwarded to the upstream and the JSON response returned to the
// client intact.
func TestIntegration_NonStreamingRequest(t *testing.T) {
	upstream := newMockAnthropicServer(t, "ok")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	resp := postMessages(t, proxyURL, testAPIKey, standardRequestBody())
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if result["id"] != "msg_test123" {
		t.Errorf("expected id msg_test123, got %v", result["id"])
	}
	if result["type"] != "message" {
		t.Errorf("expected type 'message', got %v", result["type"])
	}

	// Verify upstream received an OAuth Bearer token.
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if len(upstream.receivedHeaders) == 0 {
		t.Fatal("upstream received no requests")
	}
	authHeader := upstream.receivedHeaders[0].Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		t.Errorf("upstream expected Authorization: Bearer ..., got %q", authHeader)
	}
}

// TestIntegration_StreamingRequest verifies that a streaming request is
// forwarded as SSE and that the client receives the expected event types.
func TestIntegration_StreamingRequest(t *testing.T) {
	upstream := newMockAnthropicServer(t, "stream")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	reqBody := standardRequestBody()
	reqBody["stream"] = true

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, proxyURL+"/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/event-stream") {
		t.Errorf("expected SSE content-type, got %q", ct)
	}

	// Read and collect all received event types.
	receivedEvents := map[string]bool{}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event:") {
			eventType := strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			receivedEvents[eventType] = true
		}
	}

	expected := []string{
		"message_start",
		"content_block_start",
		"content_block_delta",
		"content_block_stop",
		"message_delta",
		"message_stop",
	}
	for _, ev := range expected {
		if !receivedEvents[ev] {
			t.Errorf("missing expected SSE event: %q", ev)
		}
	}
}

// TestIntegration_DisguiseApplied verifies that the disguise engine applies
// headers for OAuth instances when the client is not a real Claude Code client.
func TestIntegration_DisguiseApplied(t *testing.T) {
	upstream := newMockAnthropicServer(t, "ok")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	// Send a normal request; disguise should be applied for OAuth instances.
	resp := postMessages(t, proxyURL, testAPIKey, standardRequestBody())
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	upstream.mu.Lock()
	hdrs := upstream.receivedHeaders
	upstream.mu.Unlock()

	if len(hdrs) == 0 {
		t.Fatal("upstream received no requests")
	}

	// For OAuth instances, disguise headers should be applied.
	userAgent := hdrs[0].Get("User-Agent")
	if !strings.Contains(userAgent, "claude-cli") {
		t.Errorf("expected disguise User-Agent containing 'claude-cli', got %q", userAgent)
	}
	if hdrs[0].Get("X-App") != "cli" {
		t.Errorf("expected X-App: cli, got %q", hdrs[0].Get("X-App"))
	}

	// Also verify the Engine directly applies headers.
	engine := disguise.NewEngine()
	origReq, _ := http.NewRequest(http.MethodPost, upstream.srv.URL+"/v1/messages", nil)
	upstreamReq, _ := http.NewRequest(http.MethodPost, upstream.srv.URL+"/v1/messages", nil)
	upstreamReq.Header.Set("Content-Type", "application/json")

	body := []byte(`{"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"hi"}]}`)
	_, applied := engine.Apply(origReq, upstreamReq, body, false, "seed")
	if !applied {
		t.Error("expected disguise to be applied without Claude Code client header")
	}
	if upstreamReq.Header.Get("User-Agent") == "" {
		t.Error("expected User-Agent to be set after disguise")
	}
	if upstreamReq.Header.Get("X-App") != "cli" {
		t.Errorf("expected X-App: cli, got %q", upstreamReq.Header.Get("X-App"))
	}
}

// TestIntegration_ErrorMapping verifies that when the upstream returns 503,
// the proxy maps it to 502 with an Anthropic-format error body.
func TestIntegration_ErrorMapping(t *testing.T) {
	upstream := newMockAnthropicServer(t, "error503")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	resp := postMessages(t, proxyURL, testAPIKey, standardRequestBody())
	defer func() { _ = resp.Body.Close() }()

	// Upstream 503 falls into RetryThenFailover. After exhausting retries with
	// a single instance, the proxy returns 503 (overloaded_error from
	// proxy.WriteError after retry exhaustion).
	// For a single-instance setup with 503, the proxy will eventually respond
	// with either 502 (mapped) or 503 (retry exhausted).
	// We verify that the response is in Anthropic error format regardless.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusBadGateway && resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("expected 502 or 503, got %d", resp.StatusCode)
	}

	var errResp map[string]interface{}
	if err := json.Unmarshal(body, &errResp); err != nil {
		t.Fatalf("decode error response as JSON: %v\nbody: %s", err, string(body))
	}
	if errResp["type"] != "error" {
		t.Errorf("expected error type 'error', got %v", errResp["type"])
	}
	errDetail, ok := errResp["error"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected 'error' field to be an object, got %T", errResp["error"])
	}
	if errDetail["type"] == "" {
		t.Error("expected non-empty error.type in Anthropic error format")
	}
}

// TestIntegration_HealthCheck verifies that GET /health returns HTTP 200 with
// body "ok".
func TestIntegration_HealthCheck(t *testing.T) {
	upstream := newMockAnthropicServer(t, "ok")
	cfg, instances := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg, instances)
	proxyURL := startProxyServer(t, handler)

	resp, err := http.Get(proxyURL + "/health")
	if err != nil {
		t.Fatalf("health check request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read health body: %v", err)
	}
	if string(body) != "ok" {
		t.Errorf("expected body 'ok', got %q", string(body))
	}
}
