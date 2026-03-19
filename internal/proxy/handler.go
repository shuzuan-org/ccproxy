package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/binn/ccproxy/internal/observe"
	"github.com/binn/ccproxy/internal/session"
	proxytls "github.com/binn/ccproxy/internal/tls"
	"github.com/google/uuid"
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

// Handler routes incoming /v1/messages and /v1/messages/count_tokens requests
// to upstream Anthropic accounts.
type Handler struct {
	balancer     *loadbalancer.Balancer
	disguise     *disguise.Engine
	oauthManager *oauth.Manager
	httpClient   *http.Client // shared client for all accounts
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
		timeout = 600 * time.Second
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

	// Step 2: Lightweight parse to extract only model, stream flag, session ID.
	var header struct {
		Model    string `json:"model"`
		Stream   bool   `json:"stream"`
		Metadata struct {
			UserID string `json:"user_id"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(rawBody, &header); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request_error", "request body must be valid JSON")
		return
	}

	isStream := header.Stream
	originalModel := header.Model

	// Extract session ID from metadata.user_id if present.
	sessionID := ""
	if header.Metadata.UserID != "" {
		sessionID = session.ExtractSessionID(header.Metadata.UserID)
	}

	// Step 3: Get auth info from context.
	authInfo, _ := auth.GetAuthInfo(r.Context())

	// Step 4: Compose session key.
	sessionKey := session.ComposeSessionKey(authInfo.APIKeyName, sessionID)

	// Inject request context for correlation.
	requestID := uuid.New().String()
	rc := &observe.RequestContext{
		RequestID:  requestID,
		APIKeyName: authInfo.APIKeyName,
		SessionKey: sessionKey,
	}
	ctx := observe.WithRequestContext(r.Context(), rc)
	r = r.WithContext(ctx)
	log := observe.Logger(ctx)

	observe.Global.RequestsTotal.Add(1)
	log.Info("proxy request",
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
	requestFn := func(acct config.AccountConfig, requestID string) (*http.Response, int, error) {
		bodyToSend := rawBody
		for stage := 0; stage <= 2; stage++ {
			resp, statusCode, err := h.doRequest(origReq, acct, requestID, bodyToSend, isStream)
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
				errMsg := extractErrorMessage(errBody)
				log.Info("signature error detected, retrying with thinking blocks filtered",
					"account", acct.Name,
					"stage", stage,
					"error_msg", errMsg,
				)
				bodyToSend = FilterThinkingBlocks(rawBody)
				continue
			}
			if stage == 1 && (IsSignatureError(errBody) || IsToolRelatedError(errBody)) {
				errMsg := extractErrorMessage(errBody)
				log.Info("signature+tool error detected, retrying with all sensitive blocks filtered",
					"account", acct.Name,
					"stage", stage,
					"error_msg", errMsg,
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

	// Build retry callbacks for token refresh on 401.
	callbacks := loadbalancer.RetryCallbacks{
		OnTokenRefreshNeeded: func(ctx context.Context, accountName string) {
			if h.oauthManager != nil {
				h.oauthManager.MarkTokenExpired(accountName)
				h.oauthManager.ForceRefreshBackground(ctx, accountName)
			}
		},
	}

	requestStart := time.Now()
	result, err := loadbalancer.ExecuteWithRetry(r.Context(), h.balancer, sessionKey, isStream, callbacks, requestFn)
	elapsed := time.Since(requestStart)

	if err != nil {
		observe.Global.RequestsError.Add(1)
		log.Error("all retries exhausted",
			"model", originalModel,
			"elapsed", elapsed.Round(time.Millisecond),
			"error", err.Error(),
		)

		// Request summary log and per-account metrics — error path.
		summaryAttrs := buildSummaryAttrs(originalModel, isStream, elapsed, result, nil)
		if result != nil {
			recordAccountMetrics(result.AccountName, result.StatusCode, true)
		}
		log.Warn("request completed", summaryAttrs...)

		// Step 6: Map internal error to Anthropic-compatible response.
		// No healthy accounts (all disabled/empty pool) → 503 api_error
		// Accounts busy or upstream retries exhausted  → 529 overloaded_error
		if errors.Is(err, loadbalancer.ErrNoHealthyAccounts) {
			WriteError(w, http.StatusServiceUnavailable, "api_error", "No available accounts")
		} else {
			WriteError(w, 529, "overloaded_error", "Overloaded")
		}
		return
	}

	observe.Global.RequestsSuccess.Add(1)
	log.Info("upstream success",
		"account", result.AccountName,
		"status", result.StatusCode,
		"model", originalModel,
		"elapsed", elapsed.Round(time.Millisecond),
	)

	// Per-account metrics recording.
	recordAccountMetrics(result.AccountName, result.StatusCode, false)

	resp := result.Response
	defer func() { _ = resp.Body.Close() }()

	// Set request ID header for client correlation.
	w.Header().Set("X-Request-ID", requestID)

	// Note: ReportResult for success is already called inside ExecuteWithRetry.
	// Only report here for error responses that need budget header tracking.

	// Step 9: Handle error responses from upstream.
	if resp.StatusCode >= 400 {
		upstreamBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
		proxyStatus, errBody := MapUpstreamError(resp.StatusCode, upstreamBody)

		log.Warn("upstream error response",
			"account", result.AccountName,
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

	var usage *UsageInfo

	if isSSE {
		// Step 7: Streaming response — forward SSE and extract usage.
		copyHeaders(w.Header(), resp.Header)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		if u, err := ForwardSSE(r.Context(), resp.Body, w, originalModel); err != nil {
			log.Error("SSE forwarding error", "error", err)
		} else {
			usage = u
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

		// Copy upstream headers only after body is successfully read.
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(respBody)
	}

	// Request summary log — success path, after SSE/JSON processing completes.
	totalElapsed := time.Since(requestStart)
	summaryAttrs := buildSummaryAttrs(originalModel, isStream, totalElapsed, result, usage)
	if result.Retries > 0 || result.Failovers > 0 {
		log.Info("request completed", summaryAttrs...)
	} else {
		log.Debug("request completed", summaryAttrs...)
	}
}

// doRequest builds and executes a single upstream request for one account attempt.
func (h *Handler) doRequest(
	origReq *http.Request,
	acct config.AccountConfig,
	requestID string, // used for tracing correlation
	rawBody []byte,
	isStream bool,
) (*http.Response, int, error) {
	ctx := origReq.Context()
	log := observe.Logger(ctx)

	// Inject per-account SOCKS5 proxy into context for fingerprintTransport.
	if acct.Proxy != "" {
		ctx = proxytls.WithProxyURL(ctx, acct.Proxy)
	}

	// Step 5a: Resolve OAuth token.
	if h.oauthManager == nil {
		log.Error("oauth manager not configured", "account", acct.Name)
		return nil, 0, fmt.Errorf("oauth manager not configured for account %q", acct.Name)
	}
	token, err := h.oauthManager.GetValidToken(ctx, acct.Name)
	if err != nil {
		log.Error("oauth token error", "account", acct.Name, "error", err.Error())
		return nil, 401, fmt.Errorf("get oauth token: %w", err)
	}
	log.Debug("oauth token resolved",
		"account", acct.Name,
		"expires_in", time.Until(token.ExpiresAt).String(),
	)
	authHeader := "Bearer " + token.AccessToken

	// Step 5b: Apply disguise if needed (OAuth and not Claude Code client).
	body := rawBody

	// Build upstream URL dynamically from request path.
	upstreamURL := h.baseURL + origReq.URL.Path

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

	// Step 5b: Apply disguise (all accounts are OAuth).
	// Use origReq for Claude Code client detection (upstreamReq lacks User-Agent, X-App headers).
	disguised := false
	if h.disguise != nil {
		sessionSeed := origReq.Header.Get("X-Session-Seed")
		if sessionSeed == "" {
			sessionSeed = upstreamURL // fallback seed
		}
		var modifiedBody []byte
		modifiedBody, disguised = h.disguise.Apply(origReq, upstreamReq, body, isStream, sessionSeed, acct.Name)
		body = modifiedBody
		log.Debug("disguise applied", "account", acct.Name, "disguised", disguised)
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
			log.Debug("request cancelled", "account", acct.Name, "error", ctx.Err().Error())
			return nil, 0, ctx.Err()
		}
		log.Error("upstream network error", "account", acct.Name, "error", err.Error())
		return nil, 503, fmt.Errorf("upstream request failed: %w", err)
	}

	if resp.StatusCode >= 400 {
		log.Warn("upstream returned error",
			"account", acct.Name,
			"status", resp.StatusCode,
			"url", upstreamReq.URL.String(),
		)
	}

	return resp, resp.StatusCode, nil
}

// hopByHopHeaders lists headers that must not be forwarded by proxies.
var hopByHopHeaders = map[string]bool{
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

// copyHeaders copies response headers from src to dst, skipping hop-by-hop headers.
func copyHeaders(dst, src http.Header) {
	for k, vals := range src {
		if hopByHopHeaders[k] {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// buildSummaryAttrs constructs the common structured log attributes for request summary.
func buildSummaryAttrs(model string, isStream bool, elapsed time.Duration, result *loadbalancer.RetryResult, usage *UsageInfo) []any {
	attrs := []any{
		"model", model,
		"stream", isStream,
		"elapsed", elapsed.Round(time.Millisecond),
	}
	if result != nil {
		attrs = append(attrs,
			"account", result.AccountName,
			"status", result.StatusCode,
			"retries", result.Retries,
			"failovers", result.Failovers,
			"accounts_tried", result.AccountsTried,
		)
	}
	if usage != nil {
		attrs = append(attrs,
			"input_tokens", usage.InputTokens,
			"output_tokens", usage.OutputTokens,
			"cache_creation", usage.CacheCreationInputTokens,
			"cache_read", usage.CacheReadInputTokens,
		)
	}
	return attrs
}

// recordAccountMetrics updates per-account request counters.
func recordAccountMetrics(accountName string, statusCode int, isError bool) {
	im := observe.Global.Account(accountName)
	im.RequestsTotal.Add(1)
	if isError || statusCode < 200 || statusCode >= 300 {
		im.RequestsError.Add(1)
	} else {
		im.RequestsSuccess.Add(1)
	}
}

// truncateBody returns a string representation of body, truncated to maxLen bytes.
func truncateBody(body []byte, maxLen int) string {
	if len(body) <= maxLen {
		return string(body)
	}
	return string(body[:maxLen]) + "...(truncated)"
}

// extractErrorMessage extracts the error.message field from an API error response body.
func extractErrorMessage(body []byte) string {
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "(parse failed)"
	}
	msg := parsed.Error.Message
	if len(msg) > 200 {
		return msg[:200] + "..."
	}
	return msg
}
