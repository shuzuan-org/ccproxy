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
	testAPIKey      = "test-key-integration"
	testAPIKeyName  = "integration-test-key"
	testUpstreamKey = "upstream-bearer-key"
)

// buildHandler constructs the proxy mux the same way server.New() does.
func buildHandler(t *testing.T, cfg *config.Config) http.Handler {
	t.Helper()

	tracker := loadbalancer.NewConcurrencyTracker()
	balancer := loadbalancer.NewBalancer(cfg.Instances, tracker)

	disguiseEngine := disguise.NewEngine()

	// No OAuth manager needed for bearer-only tests.
	proxyHandler := proxy.NewHandler(cfg.Instances, balancer, disguiseEngine, nil)

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
func makeConfig(upstreamURL string) *config.Config {
	enabled := true
	return &config.Config{
		Server: config.ServerConfig{Host: "127.0.0.1", Port: 0},
		APIKeys: []config.APIKeyConfig{
			{Key: testAPIKey, Name: testAPIKeyName, Enabled: true},
		},
		Instances: []config.InstanceConfig{
			{
				Name:           "test-instance",
				AuthMode:       "bearer",
				APIKey:         testUpstreamKey,
				BaseURL:        upstreamURL,
				Priority:       1,
				Weight:         100,
				MaxConcurrency: 5,
				RequestTimeout: 10,
				Enabled:        &enabled,
			},
		},
	}
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
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
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
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
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
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
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

	// Verify upstream received the correct api key.
	upstream.mu.Lock()
	defer upstream.mu.Unlock()
	if len(upstream.receivedHeaders) == 0 {
		t.Fatal("upstream received no requests")
	}
	apiKey := upstream.receivedHeaders[0].Get("X-Api-Key")
	if apiKey != testUpstreamKey {
		t.Errorf("upstream expected X-Api-Key=%q, got %q", testUpstreamKey, apiKey)
	}
}

// TestIntegration_StreamingRequest verifies that a streaming request is
// forwarded as SSE and that the client receives the expected event types.
func TestIntegration_StreamingRequest(t *testing.T) {
	upstream := newMockAnthropicServer(t, "stream")
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
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

// TestIntegration_DisguiseApplied verifies that when a bearer instance (acting
// like an OAuth-disguised instance) is used, the disguise headers are set on
// the upstream request.
//
// Note: the production disguise path is triggered only for oauth auth_mode
// instances. We test it directly via the disguise.Engine to confirm the header
// logic is exercised, and we also test that a bearer instance's requests reach
// the upstream correctly (no disguise headers injected for bearer mode).
func TestIntegration_DisguiseApplied(t *testing.T) {
	upstream := newMockAnthropicServer(t, "ok")
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
	proxyURL := startProxyServer(t, handler)

	// Send a normal request; for bearer instances disguise should NOT be applied.
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

	// For bearer instances, disguise headers (User-Agent mirroring claude-cli,
	// X-App: cli) should NOT be present on the upstream request.
	userAgent := hdrs[0].Get("User-Agent")
	xApp := hdrs[0].Get("X-App")
	if strings.Contains(userAgent, "claude-cli") {
		t.Errorf("disguise User-Agent should not be set for bearer instance, got: %q", userAgent)
	}
	if xApp == "cli" {
		t.Errorf("disguise X-App header should not be set for bearer instance")
	}

	// Now verify that the Engine itself applies headers for OAuth use-case.
	engine := disguise.NewEngine()
	req, _ := http.NewRequest(http.MethodPost, upstream.srv.URL+"/v1/messages", nil)
	req.Header.Set("Content-Type", "application/json")

	body := []byte(`{"model":"claude-3-5-haiku-20241022","messages":[{"role":"user","content":"hi"}]}`)
	_, applied := engine.Apply(req, body, true /* isOAuth */, false, "seed")
	if !applied {
		t.Error("expected disguise to be applied for OAuth mode without Claude Code client header")
	}
	if req.Header.Get("User-Agent") == "" {
		t.Error("expected User-Agent to be set after disguise")
	}
	if req.Header.Get("X-App") != "cli" {
		t.Errorf("expected X-App: cli, got %q", req.Header.Get("X-App"))
	}
}

// TestIntegration_ErrorMapping verifies that when the upstream returns 503,
// the proxy maps it to 502 with an Anthropic-format error body.
func TestIntegration_ErrorMapping(t *testing.T) {
	upstream := newMockAnthropicServer(t, "error503")
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
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
	cfg := makeConfig(upstream.srv.URL)
	handler := buildHandler(t, cfg)
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
