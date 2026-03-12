package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
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
	tokenURL string
	client   *http.Client
}

func NewAnthropicProvider() *AnthropicProvider {
	return &AnthropicProvider{
		tokenURL: DefaultTokenURL,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
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

	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(string(jsonBody)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "axios/1.8.4")

	client := p.client
	if proxyURL != "" {
		client = newProxyClient(proxyURL)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		slog.Error("oauth: token endpoint error",
			"status", resp.StatusCode,
			"body", string(respBody),
			"grant_type", body["grant_type"],
		)
		return nil, fmt.Errorf("token request failed: status %d: %s", resp.StatusCode, string(respBody))
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

// newProxyClient creates an http.Client that routes requests through a SOCKS5 proxy.
func newProxyClient(proxyURL string) *http.Client {
	u, err := url.Parse(proxyURL)
	if err != nil {
		// Fall back to default client on parse error.
		return &http.Client{Timeout: 30 * time.Second}
	}

	var auth *proxy.Auth
	if u.User != nil {
		auth = &proxy.Auth{User: u.User.Username()}
		if p, ok := u.User.Password(); ok {
			auth.Password = p
		}
	}

	dialer, err := proxy.SOCKS5("tcp", u.Host, auth, &net.Dialer{Timeout: 30 * time.Second})
	if err != nil {
		return &http.Client{Timeout: 30 * time.Second}
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}
}
