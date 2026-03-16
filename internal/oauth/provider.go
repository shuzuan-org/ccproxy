package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/netutil"
)

// Anthropic OAuth constants — hardcoded, these do not change.
const (
	ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	AuthURL     = "https://claude.ai/oauth/authorize"
	DefaultTokenURL = "https://platform.claude.com/v1/oauth/token"
	RedirectURI = "https://platform.claude.com/oauth/code/callback"
	Scopes      = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers"
)

type AnthropicProvider struct {
	tokenURL     string
	client       *http.Client
	proxyClients sync.Map // proxyURL → *http.Client
}

func NewAnthropicProvider() *AnthropicProvider {
	return &AnthropicProvider{
		tokenURL: DefaultTokenURL,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// SetTokenURL overrides the token endpoint URL (for testing only).
func (p *AnthropicProvider) SetTokenURL(url string) {
	p.tokenURL = url
}

// AuthorizationURL builds the OAuth authorization URL with PKCE parameters.
// Mirrors sub2api's BuildAuthorizationURL: manual Sprintf, scope uses "+", fixed param order.
func (p *AnthropicProvider) AuthorizationURL(state, codeChallenge string) string {
	encodedRedirectURI := url.QueryEscape(RedirectURI)
	encodedScope := strings.ReplaceAll(url.QueryEscape(Scopes), "%20", "+")

	return fmt.Sprintf("%s?code=true&client_id=%s&response_type=code&redirect_uri=%s&scope=%s&code_challenge=%s&code_challenge_method=S256&state=%s",
		AuthURL,
		ClientID,
		encodedRedirectURI,
		encodedScope,
		codeChallenge,
		state,
	)
}

// ExchangeCode exchanges an authorization code for tokens.
// The code may contain a state suffix in the format "authCode#state".
// If proxyURL is non-empty, the token request is routed through the SOCKS5 proxy.
func (p *AnthropicProvider) ExchangeCode(ctx context.Context, code, codeVerifier, proxyURL string) (*OAuthToken, error) {
	slog.Info("oauth: exchanging authorization code",
		"code_len", len(code),
		"has_state", strings.Contains(code, "#"),
	)

	// Parse code which may contain state in format "authCode#state"
	authCode := code
	codeState := ""
	if idx := strings.Index(code, "#"); idx != -1 {
		authCode = code[:idx]
		codeState = code[idx+1:]
	}

	body := map[string]any{
		"code":          authCode,
		"grant_type":    "authorization_code",
		"client_id":     ClientID,
		"redirect_uri":  RedirectURI,
		"code_verifier": codeVerifier,
	}
	if codeState != "" {
		body["state"] = codeState
	}

	token, err := p.tokenRequest(ctx, body, proxyURL)
	if err != nil {
		slog.Error("oauth: code exchange failed", "error", err.Error())
		return nil, err
	}
	slog.Info("oauth: code exchange success", "expires_in", time.Until(token.ExpiresAt).String())
	return token, nil
}

// RefreshToken refreshes an OAuth token.
// If proxyURL is non-empty, the token request is routed through the SOCKS5 proxy.
func (p *AnthropicProvider) RefreshToken(ctx context.Context, refreshToken, proxyURL string) (*OAuthToken, error) {
	slog.Info("oauth: refreshing token")
	body := map[string]any{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     ClientID,
	}
	token, err := p.tokenRequest(ctx, body, proxyURL)
	if err != nil {
		slog.Error("oauth: token refresh failed", "error", err.Error())
		return nil, err
	}
	slog.Info("oauth: token refresh success", "expires_in", time.Until(token.ExpiresAt).String())
	return token, nil
}

func (p *AnthropicProvider) tokenRequest(ctx context.Context, body map[string]any, proxyURL string) (*OAuthToken, error) {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	slog.Debug("oauth: token request body", "body", string(jsonBody), "url", p.tokenURL)

	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "axios/1.8.4")

	client := p.client
	if proxyURL != "" {
		slog.Debug("oauth: using SOCKS5 proxy for token request", "proxy_host", netutil.MaskProxyURL(proxyURL), "grant_type", body["grant_type"])
		client = p.getProxyClient(proxyURL)
	} else {
		slog.Debug("oauth: using direct connection for token request", "grant_type", body["grant_type"])
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		slog.Error("oauth: token request network error",
			"grant_type", body["grant_type"],
			"via_proxy", proxyURL != "",
			"elapsed", time.Since(start).String(),
			"error", err.Error(),
		)
		return nil, err
	}
	slog.Debug("oauth: token request completed", "grant_type", body["grant_type"], "status", resp.StatusCode, "elapsed", time.Since(start).String())
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		// Read body for diagnostics but do NOT include raw content in returned errors
		// to avoid leaking potential token values per CLAUDE.md guidelines.
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		slog.Error("oauth: token endpoint error",
			"status", resp.StatusCode,
			"body", string(respBody),
			"grant_type", body["grant_type"],
		)
		return nil, fmt.Errorf("token request failed: status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &OAuthToken{
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scope:        tokenResp.Scope,
	}, nil
}

// getProxyClient returns a cached HTTP client for the given SOCKS5 proxy URL.
func (p *AnthropicProvider) getProxyClient(proxyURL string) *http.Client {
	if v, ok := p.proxyClients.Load(proxyURL); ok {
		return v.(*http.Client)
	}

	dialer, err := netutil.NewSOCKS5Dialer(proxyURL)
	if err != nil {
		slog.Error("oauth: SOCKS5 dialer creation failed, falling back to direct", "error", err.Error())
		return p.client
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}
	// Store returns the existing value if another goroutine stored first.
	actual, _ := p.proxyClients.LoadOrStore(proxyURL, client)
	return actual.(*http.Client)
}
