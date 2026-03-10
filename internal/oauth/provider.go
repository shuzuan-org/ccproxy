package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

type AnthropicProvider struct {
	config config.OAuthProviderConfig
	client *http.Client
}

func NewAnthropicProvider(cfg config.OAuthProviderConfig) *AnthropicProvider {
	return &AnthropicProvider{
		config: cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// AuthorizationURL builds the OAuth authorization URL with PKCE parameters.
func (p *AnthropicProvider) AuthorizationURL(state, codeChallenge string) string {
	u, _ := url.Parse(p.config.AuthURL)
	q := u.Query()
	q.Set("client_id", p.config.ClientID)
	q.Set("redirect_uri", p.config.RedirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("scope", strings.Join(p.config.Scopes, " "))
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *AnthropicProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
		"client_id":     {p.config.ClientID},
		"redirect_uri":  {p.config.RedirectURI},
	}
	return p.tokenRequest(ctx, data)
}

// RefreshToken refreshes an OAuth token.
func (p *AnthropicProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {p.config.ClientID},
	}
	return p.tokenRequest(ctx, data)
}

func (p *AnthropicProvider) tokenRequest(ctx context.Context, data url.Values) (*OAuthToken, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
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
