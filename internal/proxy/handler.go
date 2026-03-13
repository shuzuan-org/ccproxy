package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/auth"
	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/binn/ccproxy/internal/session"
	proxytls "github.com/binn/ccproxy/internal/tls"
)

const maxResponseBodySize int64 = 8 << 20 // 8MB

// forwardHeaders is the whitelist of headers forwarded from client to upstream.
// Aligned with sub2api's allowedHeaders. For non-CC (disguised) requests,
// ApplyHeaders() overwrites all stainless/user-agent headers anyway.
var forwardHeaders = []string{
	"Content-Type", "Accept", "Accept-Language",
	"Anthropic-Version", "Anthropic-Beta",
	"User-Agent", "X-Api-Key", "X-App",
	"X-Stainless-Lang", "X-Stainless-Package-Version",
	"X-Stainless-OS", "X-Stainless-Arch",
	"X-Stainless-Runtime", "X-Stainless-Runtime-Version",
	"X-Stainless-Retry-Count", "X-Stainless-Timeout",
	"X-Stainless-Helper-Method", "Sec-Fetch-Mode",
	"Anthropic-Dangerous-Direct-Browser-Access",
}

// Handler routes incoming /v1/messages requests to upstream Anthropic instances.
type Handler struct {
	balancer     *loadbalancer.Balancer
	disguise     *disguise.Engine
	oauthManager *oauth.Manager
	httpClient   *http.Client // shared client for all instances
	baseURL      string       // global upstream base URL
}

// NewHandler constructs a Handler with a shared HTTP client.
func NewHandler(
	baseURL string,
	requestTimeout int,
	balancer *loadbalancer.Balancer,
	disguiseEngine *disguise.Engine,
	oauthManager *oauth.Manager,
) *Handler {
	timeout := time.Duration(requestTimeout) * time.Second
	if timeout == 0 {
		timeout = 300 * time.Second
	}
	transport := proxytls.NewTransport()

	return &Handler{
		balancer:     balancer,
		disguise:     disguiseEngine,
		oauthManager: oauthManager,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		baseURL: baseURL,
	}
}

// ServeHTTP handles POST /v1/messages.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Step 1: Read request body fully (with size limit).
	defer func() { _ = r.Body.Close() }()
	rawBody, err := io.ReadAll(io.LimitReader(r.Body, maxResponseBodySize+1))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request_error", "failed to read request body")
		return
	}
	if int64(len(rawBody)) > maxResponseBodySize {
		WriteError(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")
		return
	}

	// Step 2: Parse JSON to extract model, stream flag, session ID from metadata.user_id.
	var parsed map[string]interface{}
	if err := json.Unmarshal(rawBody, &parsed); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request_error", "request body must be valid JSON")
		return
	}

	isStream, _ := parsed["stream"].(bool)
	originalModel, _ := parsed["model"].(string)

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

	slog.Info("proxy request",
		"api_key", authInfo.APIKeyName,
		"model", originalModel,
		"stream", isStream,
		"session_key", sessionKey,
	)

	// Capture the original request for disguise detection.
	origReq := r

	// Step 5: Execute with retry and failover.
	// The requestFn includes two-stage signature error retry:
	// Stage 0: send original body
	// Stage 1: on signature error → filter thinking blocks and retry
	// Stage 2: on signature+tool error → filter tool blocks and retry
	requestFn := func(inst config.InstanceConfig, requestID string) (*http.Response, int, error) {
		bodyToSend := rawBody
		for stage := 0; stage <= 2; stage++ {
			resp, statusCode, err := h.doRequest(origReq, inst, requestID, bodyToSend, parsed, isStream)
			if err != nil || statusCode != 400 || resp == nil {
				return resp, statusCode, err
			}

			// Read 400 body to check for signature error.
			errBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			_ = resp.Body.Close()
			if readErr != nil {
				return &http.Response{
					StatusCode: 400,
					Header:     resp.Header,
					Body:       io.NopCloser(bytes.NewReader(errBody)),
				}, 400, nil
			}

			if stage == 0 && IsSignatureError(errBody) {
				slog.Info("signature error detected, retrying with thinking blocks filtered",
					"instance", inst.Name,
					"stage", stage,
				)
				bodyToSend = FilterThinkingBlocks(rawBody)
				continue
			}
			if stage == 1 && IsSignatureError(errBody) && IsToolRelatedError(errBody) {
				slog.Info("signature+tool error detected, retrying with all sensitive blocks filtered",
					"instance", inst.Name,
					"stage", stage,
				)
				bodyToSend = FilterSignatureSensitiveBlocks(rawBody)
				continue
			}

			// Not a filterable error — reconstruct and return.
			return &http.Response{
				StatusCode: 400,
				Header:     resp.Header,
				Body:       io.NopCloser(bytes.NewReader(errBody)),
			}, 400, nil
		}
		return nil, 500, fmt.Errorf("exhausted signature filter stages")
	}

	requestStart := time.Now()
	result, err := loadbalancer.ExecuteWithRetry(r.Context(), h.balancer, sessionKey, requestFn)
	if err != nil {
		slog.Error("all retries exhausted",
			"api_key", authInfo.APIKeyName,
			"model", originalModel,
			"elapsed", time.Since(requestStart).String(),
			"error", err.Error(),
		)
		// Step 6: Write 503 on retry exhaustion.
		WriteError(w, http.StatusServiceUnavailable, "overloaded_error", fmt.Sprintf("upstream unavailable: %s", err.Error()))
		return
	}

	slog.Info("upstream success",
		"instance", result.InstanceName,
		"status", result.StatusCode,
		"model", originalModel,
		"elapsed", time.Since(requestStart).String(),
	)

	// Report success to health tracker.
	h.balancer.ReportResult(result.InstanceName, result.StatusCode,
		time.Since(requestStart).Microseconds(), 0)

	resp := result.Response
	defer func() { _ = resp.Body.Close() }()

	// Step 9: Handle error responses from upstream.
	if resp.StatusCode >= 400 {
		upstreamBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		proxyStatus, errBody := MapUpstreamError(resp.StatusCode, upstreamBody)

		slog.Warn("upstream error response",
			"instance", result.InstanceName,
			"upstream_status", resp.StatusCode,
			"proxy_status", proxyStatus,
			"body", truncateBody(upstreamBody, 512),
		)

		// Copy upstream response headers (excluding content-length since body changes).
		copyHeaders(w.Header(), resp.Header)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(proxyStatus)
		_, _ = w.Write(errBody)
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
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		if _, err := ForwardSSE(r.Context(), resp.Body, w, originalModel); err != nil {
			slog.Error("SSE forwarding error", "error", err)
		}
	} else {
		// Step 8: Non-streaming response — copy body and extract usage from JSON.
		respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize+1))
		if err != nil {
			WriteError(w, http.StatusBadGateway, "upstream_error", "failed to read upstream response")
			return
		}
		if int64(len(respBody)) > maxResponseBodySize {
			WriteError(w, http.StatusBadGateway, "upstream_error", "upstream response too large")
			return
		}

		// Apply disguise model ID de-normalization if needed.
		if h.disguise != nil {
			respBody = h.disguise.ApplyResponseModelID(respBody)
		}

		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
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

	// Inject per-instance SOCKS5 proxy into context for fingerprintTransport.
	if inst.Proxy != "" {
		ctx = proxytls.WithProxyURL(ctx, inst.Proxy)
	}

	// Step 5a: Resolve OAuth token.
	if h.oauthManager == nil {
		slog.Error("oauth manager not configured", "instance", inst.Name)
		return nil, 0, fmt.Errorf("oauth manager not configured for instance %q", inst.Name)
	}
	token, err := h.oauthManager.GetValidToken(ctx, inst.Name)
	if err != nil {
		slog.Error("oauth token error", "instance", inst.Name, "error", err.Error())
		return nil, 401, fmt.Errorf("get oauth token: %w", err)
	}
	slog.Debug("oauth token resolved",
		"instance", inst.Name,
		"expires_in", time.Until(token.ExpiresAt).String(),
	)
	authHeader := "Bearer " + token.AccessToken

	// Step 5b: Apply disguise if needed (OAuth and not Claude Code client).
	body := rawBody
	_ = parsed // parsed is used by disguise internally via rawBody re-parse

	// Build upstream URL.
	upstreamURL := h.baseURL + "/v1/messages"

	// Build upstream request (will be modified before sending).
	upstreamReq, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("build upstream request: %w", err)
	}

	// Copy whitelisted headers from original request (aligned with sub2api allowedHeaders).
	// For non-CC clients, disguise ApplyHeaders() will overwrite these anyway.
	for _, hdr := range forwardHeaders {
		if val := origReq.Header.Get(hdr); val != "" {
			upstreamReq.Header.Set(hdr, val)
		}
	}

	// Set default Content-Type if missing.
	if upstreamReq.Header.Get("Content-Type") == "" {
		upstreamReq.Header.Set("Content-Type", "application/json")
	}

	// Step 5b: Apply disguise (all instances are OAuth).
	// Use origReq for Claude Code client detection (upstreamReq lacks User-Agent, X-App headers).
	disguised := false
	if h.disguise != nil {
		sessionSeed := origReq.Header.Get("X-Session-Seed")
		if sessionSeed == "" {
			sessionSeed = upstreamURL // fallback seed
		}
		var modifiedBody []byte
		modifiedBody, disguised = h.disguise.Apply(origReq, upstreamReq, body, isStream, sessionSeed, inst.Name)
		body = modifiedBody
		slog.Debug("disguise applied", "instance", inst.Name, "disguised", disguised)
	}

	// Step 5d: Apply disguise URL modification for OAuth.
	if disguised {
		upstreamReq.URL, err = upstreamReq.URL.Parse(h.disguise.ApplyToURL(upstreamURL))
		if err != nil {
			return nil, 0, fmt.Errorf("apply disguise URL: %w", err)
		}
	}

	// Step 5e: Set auth header (always OAuth Bearer).
	upstreamReq.Header.Set("Authorization", authHeader)
	upstreamReq.Header.Del("X-Api-Key")

	// Step 5f: Set request body.
	upstreamReq.Body = io.NopCloser(bytes.NewReader(body))
	upstreamReq.ContentLength = int64(len(body))

	// Step 5g: Send request with shared HTTP client.
	resp, err := h.httpClient.Do(upstreamReq)
	if err != nil {
		// Network-level error: treat as 503 for retry classification.
		if ctx.Err() != nil {
			slog.Debug("request cancelled", "instance", inst.Name, "error", ctx.Err().Error())
			return nil, 0, ctx.Err()
		}
		slog.Error("upstream network error", "instance", inst.Name, "error", err.Error())
		return nil, 503, fmt.Errorf("upstream request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		slog.Warn("upstream returned error",
			"instance", inst.Name,
			"status", resp.StatusCode,
			"url", upstreamReq.URL.String(),
		)
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

// truncateBody returns a string representation of body, truncated to maxLen bytes.
func truncateBody(body []byte, maxLen int) string {
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "...(truncated)"
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
