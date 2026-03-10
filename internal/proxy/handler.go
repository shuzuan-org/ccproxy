package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/auth"
	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/binn/ccproxy/internal/observability"
	"github.com/binn/ccproxy/internal/session"
	proxytls "github.com/binn/ccproxy/internal/tls"
)

// Handler routes incoming /v1/messages requests to upstream Anthropic instances.
type Handler struct {
	balancer     *loadbalancer.Balancer
	disguise     *disguise.Engine
	oauthManager *oauth.Manager
	logger       *observability.RequestLogger
	httpClients  map[string]*http.Client        // instanceName → client
	instances    map[string]config.InstanceConfig // instanceName → config
}

// NewHandler constructs a Handler and pre-builds per-instance HTTP clients.
func NewHandler(
	instances []config.InstanceConfig,
	balancer *loadbalancer.Balancer,
	disguiseEngine *disguise.Engine,
	oauthManager *oauth.Manager,
	logger *observability.RequestLogger,
) *Handler {
	httpClients := make(map[string]*http.Client, len(instances))
	instanceMap := make(map[string]config.InstanceConfig, len(instances))

	for _, inst := range instances {
		transport := proxytls.NewTransport(inst.TLSFingerprint)
		timeout := time.Duration(inst.RequestTimeout) * time.Second
		if timeout == 0 {
			timeout = 300 * time.Second
		}
		httpClients[inst.Name] = &http.Client{
			Transport: transport,
			Timeout:   timeout,
		}
		instanceMap[inst.Name] = inst
	}

	return &Handler{
		balancer:     balancer,
		disguise:     disguiseEngine,
		oauthManager: oauthManager,
		logger:       logger,
		httpClients:  httpClients,
		instances:    instanceMap,
	}
}

// ServeHTTP handles POST /v1/messages.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Step 1: Read request body fully.
	defer func() { _ = r.Body.Close() }()
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request_error", "failed to read request body")
		return
	}

	// Step 2: Parse JSON to extract model, stream flag, session ID from metadata.user_id.
	var parsed map[string]interface{}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request_error", "request body must be valid JSON")
		return
	}

	model, _ := parsed["model"].(string)
	isStream, _ := parsed["stream"].(bool)

	// Extract session ID from metadata.user_id if present.
	sessionID := ""
	if meta, ok := parsed["metadata"].(map[string]interface{}); ok {
		if userID, ok := meta["user_id"].(string); ok {
			sessionID = session.ExtractSessionID(userID)
		}
	}

	// Step 3: Get auth info from context.
	authInfo, _ := auth.GetAuthInfo(r.Context())

	// Step 4: Compose session key.
	sessionKey := session.ComposeSessionKey(authInfo.APIKeyName, sessionID)

	// Capture the original request for disguise detection.
	origReq := r

	// Step 5: Execute with retry and failover.
	requestFn := func(inst config.InstanceConfig, requestID string) (*http.Response, int, error) {
		return h.doRequest(origReq, inst, requestID, rawBody, parsed, isStream)
	}

	result, err := loadbalancer.ExecuteWithRetry(r.Context(), h.balancer, sessionKey, requestFn)
	if err != nil {
		// Step 6: Write 503 on retry exhaustion.
		WriteError(w, http.StatusServiceUnavailable, "overloaded_error", fmt.Sprintf("upstream unavailable: %s", err.Error()))
		h.logEvent(observability.RequestEvent{
			APIKeyName:   authInfo.APIKeyName,
			Model:        model,
			Status:       "failure",
			ErrorMessage: err.Error(),
			DurationMs:   time.Since(startTime).Milliseconds(),
			SessionID:    sessionID,
		})
		return
	}

	resp := result.Response
	defer func() { _ = resp.Body.Close() }()

	// Step 9: Handle error responses from upstream.
	if resp.StatusCode >= 400 {
		upstreamBody, _ := io.ReadAll(resp.Body)
		proxyStatus, errBody := MapUpstreamError(resp.StatusCode, upstreamBody)

		// Copy upstream response headers (excluding content-length since body changes).
		copyHeaders(w.Header(), resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(proxyStatus)
		_, _ = w.Write(errBody)

		h.logEvent(observability.RequestEvent{
			APIKeyName:   authInfo.APIKeyName,
			InstanceName: result.InstanceName,
			Model:        model,
			Status:       "business_error",
			ErrorType:    fmt.Sprintf("upstream_%d", resp.StatusCode),
			DurationMs:   time.Since(startTime).Milliseconds(),
			SessionID:    sessionID,
		})
		return
	}

	// Step 7/8: Success path.
	contentType := resp.Header.Get("Content-Type")
	isSSE := strings.Contains(contentType, "text/event-stream")

	// Copy safe upstream headers to client.
	copyHeaders(w.Header(), resp.Header)

	if isSSE {
		// Step 7: Streaming response — forward SSE and extract usage.
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		usage, _ := ForwardSSE(r.Context(), resp.Body, w)

		var usageInfo UsageInfo
		if usage != nil {
			usageInfo = *usage
		}

		h.logEvent(observability.RequestEvent{
			APIKeyName:               authInfo.APIKeyName,
			InstanceName:             result.InstanceName,
			Model:                    model,
			Status:                   "success",
			InputTokens:              usageInfo.InputTokens,
			OutputTokens:             usageInfo.OutputTokens,
			CacheCreationInputTokens: usageInfo.CacheCreationInputTokens,
			CacheReadInputTokens:     usageInfo.CacheReadInputTokens,
			DurationMs:               time.Since(startTime).Milliseconds(),
			SessionID:                sessionID,
		})
	} else {
		// Step 8: Non-streaming response — copy body and extract usage from JSON.
		respBody, _ := io.ReadAll(resp.Body)

		// Apply disguise model ID de-normalization if needed.
		if h.disguise != nil {
			respBody = h.disguise.ApplyResponseModelID(respBody)
		}

		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)

		// Extract usage from JSON response body.
		usageInfo := extractUsageFromJSON(respBody)

		h.logEvent(observability.RequestEvent{
			APIKeyName:               authInfo.APIKeyName,
			InstanceName:             result.InstanceName,
			Model:                    model,
			Status:                   "success",
			InputTokens:              usageInfo.InputTokens,
			OutputTokens:             usageInfo.OutputTokens,
			CacheCreationInputTokens: usageInfo.CacheCreationInputTokens,
			CacheReadInputTokens:     usageInfo.CacheReadInputTokens,
			DurationMs:               time.Since(startTime).Milliseconds(),
			SessionID:                sessionID,
		})
	}
}

// doRequest builds and executes a single upstream request for one instance attempt.
func (h *Handler) doRequest(
	origReq *http.Request,
	inst config.InstanceConfig,
	_ string, // requestID reserved for future tracing
	rawBody []byte,
	parsed map[string]interface{},
	isStream bool,
) (*http.Response, int, error) {
	ctx := origReq.Context()

	// Step 5a: Resolve auth token.
	var authHeader string
	if inst.IsOAuth() {
		if h.oauthManager == nil {
			return nil, 0, fmt.Errorf("oauth manager not configured for instance %q", inst.Name)
		}
		token, err := h.oauthManager.GetValidToken(ctx, inst.OAuthProvider)
		if err != nil {
			return nil, 401, fmt.Errorf("get oauth token: %w", err)
		}
		authHeader = "Bearer " + token.AccessToken
	} else {
		authHeader = "" // will be set as x-api-key below
	}

	// Step 5b: Apply disguise if needed (OAuth and not Claude Code client).
	body := rawBody
	_ = parsed // parsed is used by disguise internally via rawBody re-parse

	// Build upstream URL.
	upstreamURL := inst.BaseURL + "/v1/messages"

	// Build upstream request (will be modified before sending).
	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build upstream request: %w", err)
	}

	// Copy relevant headers from original request.
	for _, hdr := range []string{
		"Content-Type",
		"Anthropic-Version",
		"Anthropic-Beta",
		"X-Api-Key",
	} {
		if val := origReq.Header.Get(hdr); val != "" {
			upstreamReq.Header.Set(hdr, val)
		}
	}

	// Set default Content-Type if missing.
	if upstreamReq.Header.Get("Content-Type") == "" {
		upstreamReq.Header.Set("Content-Type", "application/json")
	}

	// Step 5b: Apply disguise for OAuth instances not already Claude Code.
	disguised := false
	if inst.IsOAuth() && h.disguise != nil {
		sessionSeed := origReq.Header.Get("X-Session-Seed")
		if sessionSeed == "" {
			sessionSeed = upstreamURL // fallback seed
		}
		var modifiedBody []byte
		modifiedBody, disguised = h.disguise.Apply(upstreamReq, body, true, isStream, sessionSeed)
		body = modifiedBody
	}

	// Step 5d: Apply disguise URL modification for OAuth.
	if disguised {
		upstreamReq.URL, err = upstreamReq.URL.Parse(h.disguise.ApplyToURL(upstreamURL))
		if err != nil {
			return nil, 0, fmt.Errorf("apply disguise URL: %w", err)
		}
	}

	// Step 5e: Set auth header.
	if inst.IsOAuth() {
		upstreamReq.Header.Set("Authorization", authHeader)
		upstreamReq.Header.Del("X-Api-Key")
	} else {
		upstreamReq.Header.Set("X-Api-Key", inst.APIKey)
		upstreamReq.Header.Del("Authorization")
	}

	// Step 5f: Set request body.
	upstreamReq.Body = io.NopCloser(bytes.NewReader(body))
	upstreamReq.ContentLength = int64(len(body))

	// Step 5g: Send request with instance-specific HTTP client.
	client, ok := h.httpClients[inst.Name]
	if !ok {
		// Fallback to default client.
		client = http.DefaultClient
	}

	resp, err := client.Do(upstreamReq)
	if err != nil {
		// Network-level error: treat as 503 for retry classification.
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		return nil, 503, fmt.Errorf("upstream request failed: %w", err)
	}

	return resp, resp.StatusCode, nil
}

// copyHeaders copies response headers from src to dst, skipping hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	hopByHop := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
		"Content-Length":      true, // recalculated
	}
	for k, vals := range src {
		if hopByHop[k] {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// usageResponse is a minimal struct for extracting usage from a non-streaming response body.
type usageResponse struct {
	Usage struct {
		InputTokens              int64 `json:"input_tokens"`
		OutputTokens             int64 `json:"output_tokens"`
		CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
		CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	} `json:"usage"`
}

// extractUsageFromJSON parses a non-streaming response body to extract token usage.
func extractUsageFromJSON(body []byte) UsageInfo {
	var ur usageResponse
	if err := json.Unmarshal(body, &ur); err != nil {
		return UsageInfo{}
	}
	return UsageInfo{
		InputTokens:              ur.Usage.InputTokens,
		OutputTokens:             ur.Usage.OutputTokens,
		CacheCreationInputTokens: ur.Usage.CacheCreationInputTokens,
		CacheReadInputTokens:     ur.Usage.CacheReadInputTokens,
	}
}

// logEvent sends a RequestEvent to the logger if one is configured.
func (h *Handler) logEvent(event observability.RequestEvent) {
	if h.logger == nil {
		return
	}
	h.logger.Log(event)
}
