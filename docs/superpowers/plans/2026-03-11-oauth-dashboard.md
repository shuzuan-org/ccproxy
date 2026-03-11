# OAuth Dashboard Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace admin dashboard with an OAuth management page; simplify config by removing provider section and hardcoding Anthropic constants; change token store to per-instance keying.

**Architecture:** Remove `OAuthProviderConfig` and `oauth_provider` field. Hardcode Anthropic OAuth constants in `internal/oauth/provider.go`. Rewrite `Manager` to key by instance name. Add PKCE session store and 4 new API endpoints to `admin.Handler`. Replace the HTML dashboard with a focused OAuth instances table plus login/refresh/logout actions.

**Tech Stack:** Go 1.22, net/http, embed, AES-256-GCM, PKCE (S256), inline HTML/CSS/JS

**Spec:** `docs/superpowers/specs/2026-03-11-oauth-dashboard-design.md`

---

## Chunk 1: Config and Provider Simplification

### Task 1: Remove OAuthProviderConfig from config

**Files:**
- Modify: `internal/config/config.go:17-58` (structs), `internal/config/config.go:140-165` (validation)
- Modify: `internal/config/config_test.go`

- [ ] **Step 1: Update config_test.go — remove provider-related test assertions**

In `internal/config/config_test.go`, the test TOML includes `oauth_provider = "anthropic"` and `[[oauth_providers]]` section. The test assertions check `alice.OAuthProvider`, `cfg.OAuthProviders`. Remove all of these. Also remove the validation test case for `"unknown oauth_provider"`.

Update `TestLoad_ValidConfig`:
- Remove `oauth_provider = "anthropic"` from test TOML (line 42)
- Remove `[[oauth_providers]]` block from test TOML (lines 61-67)
- Remove assertion for `alice.OAuthProvider` (lines 113-115)
- Remove assertions for `cfg.OAuthProviders` (lines 144-149)

Update `TestLoad_ValidationErrors`:
- Remove the test case with `wantErr: "unknown oauth_provider"` (lines 256-263)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/... -v -race`
Expected: compilation errors (OAuthProvider, OAuthProviders, OAuthProviderConfig no longer match code)

- [ ] **Step 3: Update config.go — remove provider structs and fields**

In `internal/config/config.go`:

Remove `OAuthProviderConfig` struct (lines 51-58):
```go
// DELETE entire struct
type OAuthProviderConfig struct {
	Name        string   `toml:"name"`
	ClientID    string   `toml:"client_id"`
	AuthURL     string   `toml:"auth_url"`
	TokenURL    string   `toml:"token_url"`
	RedirectURI string   `toml:"redirect_uri"`
	Scopes      []string `toml:"scopes"`
}
```

Remove `OAuthProviders` field from `Config` struct (line 20):
```go
// DELETE this line
OAuthProviders []OAuthProviderConfig `toml:"oauth_providers"`
```

Remove `OAuthProvider` field from `InstanceConfig` (line 39):
```go
// DELETE this line
OAuthProvider  string `toml:"oauth_provider"`
```

In `Validate()`, remove the oauth provider map and check (lines 142-163):
```go
// DELETE: build oauth provider name set
oauthProviders := make(map[string]struct{}, len(c.OAuthProviders))
for _, p := range c.OAuthProviders {
    oauthProviders[p.Name] = struct{}{}
}

// DELETE: inside the instances loop
if inst.IsOAuth() {
    if _, ok := oauthProviders[inst.OAuthProvider]; !ok {
        errs = append(errs, fmt.Errorf(
            "instance %q references unknown oauth_provider %q", inst.Name, inst.OAuthProvider,
        ))
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/... -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "refactor: remove OAuthProviderConfig and oauth_provider from config"
```

---

### Task 2: Hardcode Anthropic constants in provider.go

**Files:**
- Modify: `internal/oauth/provider.go`
- Modify: `internal/oauth/manager_test.go`

- [ ] **Step 1: Update manager_test.go — use new provider API**

Replace `newTestManager` helper. The new `NewAnthropicProvider()` takes no args but uses hardcoded constants. For tests, we need to override `TokenURL` to point to httptest server. Add a `newTestProvider` that creates a provider with a custom token URL:

```go
// newTestProvider creates an AnthropicProvider pointing at the given token server.
func newTestProvider(tokenServerURL string) *AnthropicProvider {
	p := NewAnthropicProvider()
	p.tokenURL = tokenServerURL
	return p
}
```

Update `TestProvider_AuthorizationURL` to use `NewAnthropicProvider()` and check hardcoded constants:

```go
func TestProvider_AuthorizationURL(t *testing.T) {
	p := NewAnthropicProvider()

	state := "test-state-value"
	challenge := "test-challenge-value"
	rawURL := p.AuthorizationURL(state, challenge)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	q := parsed.Query()

	checks := map[string]string{
		"client_id":             ClientID,
		"redirect_uri":          RedirectURI,
		"response_type":         "code",
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
		"state":                 state,
	}
	for key, want := range checks {
		if got := q.Get(key); got != want {
			t.Errorf("param %q: got %q, want %q", key, got, want)
		}
	}

	scope := q.Get("scope")
	if !strings.Contains(scope, "user:inference") {
		t.Errorf("scope %q missing user:inference", scope)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/oauth/... -v -race`
Expected: compilation errors

- [ ] **Step 3: Rewrite provider.go with hardcoded constants**

Replace `internal/oauth/provider.go` entirely:

```go
package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Anthropic OAuth constants — hardcoded, these do not change.
const (
	ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	AuthURL     = "https://claude.ai/oauth/authorize"
	TokenURL    = "https://platform.claude.com/v1/oauth/token"
	RedirectURI = "https://platform.claude.com/oauth/code/callback"
	Scopes      = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers"
)

type AnthropicProvider struct {
	tokenURL string
	client   *http.Client
}

func NewAnthropicProvider() *AnthropicProvider {
	return &AnthropicProvider{
		tokenURL: TokenURL,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// AuthorizationURL builds the OAuth authorization URL with PKCE parameters.
func (p *AnthropicProvider) AuthorizationURL(state, codeChallenge string) string {
	u, _ := url.Parse(AuthURL)
	q := u.Query()
	q.Set("client_id", ClientID)
	q.Set("redirect_uri", RedirectURI)
	q.Set("response_type", "code")
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("scope", Scopes)
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
		"client_id":     {ClientID},
		"redirect_uri":  {RedirectURI},
	}
	return p.tokenRequest(ctx, data)
}

// RefreshToken refreshes an OAuth token.
func (p *AnthropicProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ClientID},
	}
	return p.tokenRequest(ctx, data)
}

func (p *AnthropicProvider) tokenRequest(ctx context.Context, data url.Values) (*OAuthToken, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("token request failed: status %d: %s", resp.StatusCode, string(body))
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/oauth/... -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/provider.go internal/oauth/manager_test.go
git commit -m "refactor: hardcode Anthropic OAuth constants, remove config dependency from provider"
```

---

### Task 3: Rewrite Manager to key by instance name

**Files:**
- Modify: `internal/oauth/manager.go`
- Modify: `internal/oauth/manager_test.go`

- [ ] **Step 1: Rewrite manager_test.go for instance-based API**

Replace `newTestManager`:

```go
func newTestManager(t *testing.T, tokenServerURL string) (*Manager, *TokenStore) {
	t.Helper()
	store, err := NewTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	instances := []config.InstanceConfig{
		{Name: "test-oauth", AuthMode: "oauth"},
	}
	m := NewManager(instances, store)
	// Override provider's tokenURL for testing
	m.provider.tokenURL = tokenServerURL
	return m, store
}
```

Update all test functions to use instance name `"test-oauth"` instead of provider name `"anthropic"`:
- `store.Save("test-oauth", tok)` instead of `store.Save("anthropic", tok)`
- `m.GetValidToken(ctx, "test-oauth")` instead of `m.GetValidToken(ctx, "anthropic")`
- `m.Status("test-oauth")` instead of `m.Status("anthropic")`
- `m.Logout("test-oauth")` instead of `m.Logout("anthropic")`
- `store.Load("test-oauth")` instead of `store.Load("anthropic")`

Update error message check in `TestManager_GetValidToken_NoToken_ReturnsError`:
```go
if !strings.Contains(err.Error(), "no token for instance") {
    t.Errorf("expected instance hint in error, got: %v", err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/oauth/... -v -race`
Expected: compilation errors (NewManager signature changed)

- [ ] **Step 3: Rewrite manager.go**

Replace `internal/oauth/manager.go`:

```go
package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

type Manager struct {
	instances []string // names of oauth instances
	provider  *AnthropicProvider
	store     *TokenStore
	refreshMu map[string]*sync.Mutex
}

func NewManager(allInstances []config.InstanceConfig, store *TokenStore) *Manager {
	var names []string
	refreshMu := make(map[string]*sync.Mutex)
	for _, inst := range allInstances {
		if inst.IsOAuth() {
			names = append(names, inst.Name)
			refreshMu[inst.Name] = &sync.Mutex{}
		}
	}
	return &Manager{
		instances: names,
		provider:  NewAnthropicProvider(),
		store:     store,
		refreshMu: refreshMu,
	}
}

// GetValidToken returns a valid access token for the given instance.
// If the token is about to expire (within 60s), it triggers a refresh.
func (m *Manager) GetValidToken(ctx context.Context, instanceName string) (*OAuthToken, error) {
	token, err := m.store.Load(instanceName)
	if err != nil {
		return nil, fmt.Errorf("load token: %w", err)
	}
	if token == nil {
		return nil, fmt.Errorf("no token for instance %q, run 'ccproxy oauth login %s'", instanceName, instanceName)
	}

	if time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	return m.refreshToken(ctx, instanceName, token.RefreshToken)
}

func (m *Manager) refreshToken(ctx context.Context, instanceName, refreshTokenStr string) (*OAuthToken, error) {
	mu, ok := m.refreshMu[instanceName]
	if !ok {
		return nil, fmt.Errorf("unknown instance: %s", instanceName)
	}

	mu.Lock()
	defer mu.Unlock()

	// Double-check after acquiring lock
	token, _ := m.store.Load(instanceName)
	if token != nil && time.Until(token.ExpiresAt) > 60*time.Second {
		return token, nil
	}

	newToken, err := m.provider.RefreshToken(ctx, refreshTokenStr)
	if err != nil {
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	if err := m.store.Save(instanceName, *newToken); err != nil {
		return nil, fmt.Errorf("save token: %w", err)
	}

	slog.Info("token refreshed", "instance", instanceName, "expires_at", newToken.ExpiresAt)
	return newToken, nil
}

// Status returns the token info for an instance (without triggering refresh).
func (m *Manager) Status(instanceName string) (*OAuthToken, error) {
	return m.store.Load(instanceName)
}

// Logout removes the stored token for an instance.
func (m *Manager) Logout(instanceName string) error {
	return m.store.Delete(instanceName)
}

// StartAutoRefresh starts a background goroutine that checks and refreshes tokens.
func (m *Manager) StartAutoRefresh(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, name := range m.instances {
					token, err := m.store.Load(name)
					if err != nil || token == nil {
						continue
					}
					if time.Until(token.ExpiresAt) < 60*time.Second {
						_, err := m.refreshToken(ctx, name, token.RefreshToken)
						if err != nil {
							slog.Error("auto-refresh failed", "instance", name, "error", err)
						}
					}
				}
			}
		}
	}()
}

// GetProvider returns the shared provider (for login flow).
func (m *Manager) GetProvider() *AnthropicProvider {
	return m.provider
}

// GetStore returns the token store.
func (m *Manager) GetStore() *TokenStore {
	return m.store
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/oauth/... -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/manager.go internal/oauth/manager_test.go
git commit -m "refactor: rewrite Manager to key by instance name"
```

---

### Task 4: Update proxy handler and server wiring

**Files:**
- Modify: `internal/proxy/handler.go:172` (OAuthProvider → instance name)
- Modify: `internal/proxy/handler_test.go`
- Modify: `internal/server/server.go:43`

- [ ] **Step 1: Update proxy handler — use instance name for token lookup**

In `internal/proxy/handler.go` line 172, change:
```go
// Before
token, err := h.oauthManager.GetValidToken(ctx, inst.OAuthProvider)
// After
token, err := h.oauthManager.GetValidToken(ctx, inst.Name)
```

- [ ] **Step 2: Update proxy handler_test.go**

Remove `OAuthProvider` from test instance config. Update `NewManager` call:
```go
// Before
manager := oauth.NewManager([]config.OAuthProviderConfig{
    {Name: "test-provider"},
}, store)

// After
manager := oauth.NewManager([]config.InstanceConfig{
    {Name: "test-oauth", AuthMode: "oauth"},
}, store)
```

Update token store `Save` call to use instance name instead of provider name:
```go
// Before
store.Save("test-provider", ...)
// After
store.Save("test-oauth", ...)
```

- [ ] **Step 3: Update server.go — fix NewManager call**

In `internal/server/server.go` line 43, change:
```go
// Before
oauthMgr = oauth.NewManager(cfg.OAuthProviders, store)
// After
oauthMgr = oauth.NewManager(cfg.Instances, store)
```

- [ ] **Step 4: Run all tests**

Run: `go test ./... -v -race`
Expected: PASS (may have compile errors to fix in other files)

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go internal/server/server.go
git commit -m "refactor: update proxy and server to use instance-based OAuth manager"
```

---

### Task 5: Update CLI oauth commands

**Files:**
- Modify: `internal/cli/oauth.go`

- [ ] **Step 1: Rewrite oauth.go CLI commands**

Change all 4 commands:

**oauthLoginCmd**: Change arg from `<provider>` to `<instance>`. Remove provider config lookup. Use `NewAnthropicProvider()` directly. Validate instance exists and is OAuth. Save token keyed by instance name.

**oauthStatusCmd**: Load tokens by iterating config instances (OAuth ones), not by `store.List()`.

**oauthRefreshCmd**: Change arg from `<provider>` to `<instance>`. Use `NewAnthropicProvider()`. Load/save by instance name.

**oauthLogoutCmd**: Change arg from `<provider>` to `<instance>`. Delete by instance name.

Key changes:
```go
// Login: validate instance
var inst *config.InstanceConfig
for i := range cfg.Instances {
    if cfg.Instances[i].Name == instanceName && cfg.Instances[i].IsOAuth() {
        inst = &cfg.Instances[i]
        break
    }
}
if inst == nil {
    return fmt.Errorf("instance %q not found or not an oauth instance", instanceName)
}

provider := oauth.NewAnthropicProvider()
// ... rest of flow uses instanceName for store.Save/Load
```

```go
// Status: iterate oauth instances from config
cfg, err := config.Load(cfgFile)
if err != nil {
    return fmt.Errorf("load config: %w", err)
}
store, err := oauth.NewTokenStore(dataDir)
if err != nil {
    return fmt.Errorf("open token store: %w", err)
}

fmt.Printf("%-20s %-30s %s\n", "INSTANCE", "EXPIRES AT", "STATUS")
fmt.Printf("%-20s %-30s %s\n", "--------------------", "------------------------------", "-------")

for _, inst := range cfg.Instances {
    if !inst.IsOAuth() {
        continue
    }
    token, err := store.Load(inst.Name)
    // ... same display logic but using inst.Name
}
```

```go
// Refresh: validate instance, use NewAnthropicProvider()
provider := oauth.NewAnthropicProvider()
newToken, err := provider.RefreshToken(context.Background(), existing.RefreshToken)
if err != nil {
    return fmt.Errorf("refresh token: %w", err)
}
if err := store.Save(instanceName, *newToken); err != nil {
    return fmt.Errorf("save token: %w", err)
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/cli/... -v -race 2>&1; go build ./cmd/ccproxy/`
Expected: compiles and passes

- [ ] **Step 3: Commit**

```bash
git add internal/cli/oauth.go
git commit -m "refactor: CLI oauth commands use instance names and hardcoded provider"
```

---

### Task 6: Update config.toml.example

**Files:**
- Modify: `config.toml.example`
- Modify: `config.toml` (if exists, same changes)

- [ ] **Step 1: Remove oauth_provider and [[oauth_providers]] from config files**

In `config.toml.example`, remove `oauth_provider = "anthropic"` from the `alice-oauth` instance, and remove the entire `[[oauth_providers]]` section (lines 35-41).

After:
```toml
[server]
host = "0.0.0.0"
port = 3000
log_level = "info"
admin_password = "tmLuqkQjJk2BhgyMW40vqEUKMCx10EMI"

[[api_keys]]
key = "sk-ccproxy-987313a7b186d14afe045aa16335b032"
name = "dev-team"
enabled = true

[[instances]]
name = "alice-oauth"
auth_mode = "oauth"
priority = 1
weight = 100
max_concurrency = 5
base_url = "https://api.anthropic.com"
request_timeout = 300
tls_fingerprint = true

[[instances]]
name = "bob-apikey"
auth_mode = "bearer"
api_key = "sk-ant-api03-your-key-here"
priority = 2
weight = 100
max_concurrency = 10
base_url = "https://api.anthropic.com"
request_timeout = 300
tls_fingerprint = false
enabled = false
```

Apply same changes to `config.toml` if it exists.

- [ ] **Step 2: Verify config loads**

Run: `go build ./cmd/ccproxy/ && ./bin/ccproxy test` (or compile and dry-run)
Expected: config validates successfully

- [ ] **Step 3: Commit**

```bash
git add config.toml.example config.toml
git commit -m "chore: remove oauth_providers from config examples"
```

---

## Chunk 2: PKCE Session Store and Admin API

### Task 7: Create PKCE session store

**Files:**
- Create: `internal/oauth/session.go`
- Create: `internal/oauth/session_test.go`

- [ ] **Step 1: Write session_test.go**

```go
package oauth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSessionStore_CreateAndComplete(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()

	sessionID, authURL, err := ss.Create("alice-oauth")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sessionID == "" {
		t.Fatal("empty session ID")
	}
	if !strings.Contains(authURL, "claude.ai/oauth/authorize") {
		t.Errorf("authURL missing authorize endpoint: %s", authURL)
	}
	if !strings.Contains(authURL, ClientID) {
		t.Errorf("authURL missing client_id: %s", authURL)
	}

	// Lookup should return the session
	session, ok := ss.Get(sessionID)
	if !ok {
		t.Fatal("session not found after Create")
	}
	if session.InstanceName != "alice-oauth" {
		t.Errorf("instance = %q, want alice-oauth", session.InstanceName)
	}
	if session.Verifier == "" {
		t.Error("empty verifier")
	}
	if session.State == "" {
		t.Error("empty state")
	}
}

func TestSessionStore_GetExpired(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()
	ss.ttl = 1 * time.Millisecond // override for test

	sessionID, _, err := ss.Create("bob-oauth")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, ok := ss.Get(sessionID)
	if ok {
		t.Error("expected expired session to not be found")
	}
}

func TestSessionStore_Delete(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()

	sessionID, _, _ := ss.Create("test-oauth")
	ss.Delete(sessionID)

	_, ok := ss.Get(sessionID)
	if ok {
		t.Error("session still found after Delete")
	}
}

func TestSessionStore_Cleanup(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()
	ss.ttl = 1 * time.Millisecond

	ss.Create("a")
	ss.Create("b")

	time.Sleep(5 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.StartCleanup(ctx, 10*time.Millisecond)

	time.Sleep(50 * time.Millisecond)

	ss.mu.RLock()
	count := len(ss.sessions)
	ss.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", count)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/oauth/... -run TestSessionStore -v -race`
Expected: compilation error (SessionStore not defined)

- [ ] **Step 3: Implement session.go**

```go
package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const defaultSessionTTL = 10 * time.Minute

// PKCESession stores the state of an in-progress OAuth login.
type PKCESession struct {
	InstanceName string
	Verifier     string
	State        string
	CreatedAt    time.Time
}

// SessionStore manages PKCE sessions in memory with auto-expiry.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*PKCESession
	ttl      time.Duration
}

// NewSessionStore creates a SessionStore with default 10-minute TTL.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*PKCESession),
		ttl:      defaultSessionTTL,
	}
}

// Create starts a new PKCE session for the given instance.
// Returns the session ID and the authorization URL.
func (s *SessionStore) Create(instanceName string) (sessionID, authURL string, err error) {
	verifier := GenerateVerifier()
	challenge := GenerateChallenge(verifier)
	state := GenerateState()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", err
	}
	sessionID = hex.EncodeToString(idBytes)

	provider := NewAnthropicProvider()
	authURL = provider.AuthorizationURL(state, challenge)

	s.mu.Lock()
	s.sessions[sessionID] = &PKCESession{
		InstanceName: instanceName,
		Verifier:     verifier,
		State:        state,
		CreatedAt:    time.Now(),
	}
	s.mu.Unlock()

	return sessionID, authURL, nil
}

// Get retrieves a session if it exists and is not expired.
func (s *SessionStore) Get(sessionID string) (*PKCESession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	if time.Since(session.CreatedAt) > s.ttl {
		return nil, false
	}
	return session, true
}

// Delete removes a session.
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// StartCleanup runs a background goroutine that removes expired sessions.
func (s *SessionStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				for id, session := range s.sessions {
					if time.Since(session.CreatedAt) > s.ttl {
						delete(s.sessions, id)
					}
				}
				s.mu.Unlock()
			}
		}
	}()
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/oauth/... -run TestSessionStore -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/session.go internal/oauth/session_test.go
git commit -m "feat: add PKCE session store for browser OAuth login flow"
```

---

### Task 8: Add OAuth API endpoints to admin handler

**Files:**
- Modify: `internal/admin/handler.go`
- Create: `internal/admin/handler_test.go`

- [ ] **Step 1: Write handler_test.go for OAuth endpoints**

```go
package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	tracker := loadbalancer.NewConcurrencyTracker()
	instances := []config.InstanceConfig{
		{Name: "test-oauth", AuthMode: "oauth", MaxConcurrency: 5, Priority: 1},
	}
	balancer := loadbalancer.NewBalancer(instances, tracker)
	store, err := oauth.NewTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	mgr := oauth.NewManager(instances, store)
	sessions := oauth.NewSessionStore()
	cfg := &config.Config{
		Instances: instances,
	}
	return NewHandler(balancer, mgr, sessions, cfg)
}

func TestHandleInstances_IncludesTokenStatus(t *testing.T) {
	h := newTestHandler(t)

	// Save a token for the instance
	tok := oauth.OAuthToken{
		AccessToken: "test",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	h.oauthMgr.GetStore().Save("test-oauth", tok)

	req := httptest.NewRequest("GET", "/api/instances", nil)
	w := httptest.NewRecorder()
	h.HandleInstances(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var states []InstanceState
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

func TestHandleOAuthLoginStart(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"instance": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/oauth/login/start", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginStart(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["session_id"] == "" {
		t.Error("missing session_id")
	}
	if resp["authorization_url"] == "" {
		t.Error("missing authorization_url")
	}
}

func TestHandleOAuthLoginStart_InvalidInstance(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"instance": "nonexistent"})
	req := httptest.NewRequest("POST", "/api/oauth/login/start", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginStart(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleOAuthRefresh_NoToken(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"instance": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/oauth/refresh", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthRefresh(w, req)

	// Should fail because no token stored
	if w.Code == 200 {
		t.Error("expected error when no token stored")
	}
}

func TestHandleOAuthLogout(t *testing.T) {
	h := newTestHandler(t)

	// Save a token first
	tok := oauth.OAuthToken{AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour)}
	h.oauthMgr.GetStore().Save("test-oauth", tok)

	body, _ := json.Marshal(map[string]string{"instance": "test-oauth"})
	req := httptest.NewRequest("POST", "/api/oauth/logout", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLogout(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}

	// Verify token is gone
	got, _ := h.oauthMgr.GetStore().Load("test-oauth")
	if got != nil {
		t.Error("token should be deleted after logout")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/admin/... -v -race`
Expected: compilation errors (new Handler signature, new methods)

- [ ] **Step 3: Implement updated handler.go**

Replace `internal/admin/handler.go`:

```go
package admin

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
)

//go:embed static
var staticFiles embed.FS

// Handler provides HTTP handlers for the admin dashboard.
type Handler struct {
	balancer *loadbalancer.Balancer
	oauthMgr *oauth.Manager
	sessions *oauth.SessionStore
	cfg      *config.Config
}

// NewHandler creates an admin Handler.
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
	}
}

// writeJSON writes v as JSON with Content-Type: application/json.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "json encode error", http.StatusInternalServerError)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// InstanceState holds the runtime state of a single backend instance.
type InstanceState struct {
	Name           string  `json:"name"`
	AuthMode       string  `json:"auth_mode"`
	LoadRate       int     `json:"load_rate"`
	ActiveSlots    int     `json:"active_slots"`
	MaxConcurrency int     `json:"max_concurrency"`
	Priority       int     `json:"priority"`
	Enabled        bool    `json:"enabled"`
	TokenStatus    string  `json:"token_status,omitempty"`
	TokenExpiresAt *string `json:"token_expires_at,omitempty"`
}

// tokenStatus returns a human-readable status for an OAuth token.
func tokenStatus(token *oauth.OAuthToken) string {
	if token == nil {
		return "no token"
	}
	remaining := time.Until(token.ExpiresAt)
	if remaining < 0 {
		return "expired"
	}
	if remaining < 5*time.Minute {
		return "expiring soon"
	}
	return "valid"
}

// HandleInstances returns instance status with token info for OAuth instances.
// GET /api/instances
func (h *Handler) HandleInstances(w http.ResponseWriter, r *http.Request) {
	tracker := h.balancer.GetTracker()

	// Read all OAuth instances from config (includes disabled)
	states := make([]InstanceState, 0)
	for _, inst := range h.cfg.Instances {
		if !inst.IsOAuth() {
			continue
		}

		var loadRate, activeSlots int
		if inst.IsEnabled() {
			activeSlots, _, loadRate = tracker.LoadInfo(inst.Name, inst.MaxConcurrency)
		}

		state := InstanceState{
			Name:           inst.Name,
			AuthMode:       inst.AuthMode,
			LoadRate:       loadRate,
			ActiveSlots:    activeSlots,
			MaxConcurrency: inst.MaxConcurrency,
			Priority:       inst.Priority,
			Enabled:        inst.IsEnabled(),
		}

		// Add token info
		if h.oauthMgr != nil {
			token, _ := h.oauthMgr.Status(inst.Name)
			state.TokenStatus = tokenStatus(token)
			if token != nil {
				exp := token.ExpiresAt.Format(time.RFC3339)
				state.TokenExpiresAt = &exp
			}
		}

		states = append(states, state)
	}
	writeJSON(w, states)
}

// HandleOAuthLoginStart starts a PKCE OAuth flow for an instance.
// POST /api/oauth/login/start
func (h *Handler) HandleOAuthLoginStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate instance exists and is OAuth
	if !h.isOAuthInstance(req.Instance) {
		writeError(w, http.StatusBadRequest, "instance not found or not oauth")
		return
	}

	sessionID, authURL, err := h.sessions.Create(req.Instance)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	writeJSON(w, map[string]string{
		"session_id":        sessionID,
		"authorization_url": authURL,
	})
}

// HandleOAuthLoginComplete completes a PKCE OAuth flow.
// POST /api/oauth/login/complete
func (h *Handler) HandleOAuthLoginComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	session, ok := h.sessions.Get(req.SessionID)
	if !ok {
		writeError(w, http.StatusBadRequest, "session not found or expired")
		return
	}

	// Exchange code for token
	provider := h.oauthMgr.GetProvider()
	token, err := provider.ExchangeCode(r.Context(), req.Code, session.Verifier)
	if err != nil {
		h.sessions.Delete(req.SessionID)
		writeError(w, http.StatusBadGateway, "code exchange failed: "+err.Error())
		return
	}

	// Save token keyed by instance name
	if err := h.oauthMgr.GetStore().Save(session.InstanceName, *token); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save token")
		return
	}

	h.sessions.Delete(req.SessionID)

	writeJSON(w, map[string]any{
		"ok":         true,
		"expires_at": token.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleOAuthRefresh forces a token refresh for an instance.
// POST /api/oauth/refresh
func (h *Handler) HandleOAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !h.isOAuthInstance(req.Instance) {
		writeError(w, http.StatusBadRequest, "instance not found or not oauth")
		return
	}

	// Load existing token to get refresh_token
	existing, err := h.oauthMgr.GetStore().Load(req.Instance)
	if err != nil || existing == nil {
		writeError(w, http.StatusBadRequest, "no token stored for this instance")
		return
	}
	if existing.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "no refresh token available")
		return
	}

	provider := h.oauthMgr.GetProvider()
	newToken, err := provider.RefreshToken(r.Context(), existing.RefreshToken)
	if err != nil {
		writeError(w, http.StatusBadGateway, "refresh failed: "+err.Error())
		return
	}

	if err := h.oauthMgr.GetStore().Save(req.Instance, *newToken); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save token")
		return
	}

	writeJSON(w, map[string]any{
		"ok":         true,
		"expires_at": newToken.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleOAuthLogout deletes the token for an instance.
// POST /api/oauth/logout
func (h *Handler) HandleOAuthLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.oauthMgr.GetStore().Delete(req.Instance); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete token")
		return
	}

	writeJSON(w, map[string]bool{"ok": true})
}

// HandleSessions returns active session list (placeholder).
// GET /api/sessions
func (h *Handler) HandleSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, []struct{}{})
}

// HandleDashboard serves the embedded static HTML dashboard.
// GET /admin/*
func (h *Handler) HandleDashboard() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("admin: failed to sub static fs: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}

// isOAuthInstance checks if the given name is a configured OAuth instance.
func (h *Handler) isOAuthInstance(name string) bool {
	for _, inst := range h.cfg.Instances {
		if inst.Name == name && inst.IsOAuth() {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/admin/... -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/admin/handler.go internal/admin/handler_test.go
git commit -m "feat: add OAuth API endpoints to admin handler"
```

---

### Task 9: Wire OAuth routes in server.go

**Files:**
- Modify: `internal/server/server.go`

- [ ] **Step 1: Update server.go — add session store and wire routes**

In `internal/server/server.go`, update the `New` function:

After the `oauthMgr` creation block (~line 46), add:
```go
// 3b. Create PKCE session store for browser-based OAuth login.
var oauthSessions *oauth.SessionStore
if oauthMgr != nil {
    oauthSessions = oauth.NewSessionStore()
    oauthSessions.StartCleanup(context.Background(), time.Minute)
}
```

Update admin handler creation (~line 52):
```go
// Before
adminHandler := admin.NewHandler(balancer)
// After
adminHandler := admin.NewHandler(balancer, oauthMgr, oauthSessions, cfg)
```

Add new routes after existing admin routes (~line 70):
```go
mux.Handle("/api/oauth/login/start", adminMiddleware(http.HandlerFunc(adminHandler.HandleOAuthLoginStart)))
mux.Handle("/api/oauth/login/complete", adminMiddleware(http.HandlerFunc(adminHandler.HandleOAuthLoginComplete)))
mux.Handle("/api/oauth/refresh", adminMiddleware(http.HandlerFunc(adminHandler.HandleOAuthRefresh)))
mux.Handle("/api/oauth/logout", adminMiddleware(http.HandlerFunc(adminHandler.HandleOAuthLogout)))
```

- [ ] **Step 2: Run full test suite**

Run: `go test ./... -race`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/server/server.go
git commit -m "feat: wire OAuth API routes and session store in server"
```

---

## Chunk 3: Dashboard HTML

### Task 10: Replace dashboard HTML with OAuth management page

**Files:**
- Modify: `internal/admin/static/index.html`

- [ ] **Step 1: Replace index.html**

Replace entire content of `internal/admin/static/index.html` with the new OAuth-focused dashboard. Key features:

- Single card: "OAuth Instances" table
- Columns: Name, Token Status, Expires At, Actions
- Actions: Login/Refresh/Logout buttons per row
- Login modal: shows auth URL link, has code input field, submit button
- Keep existing dark GitHub theme (CSS variables, card styles)
- 30-second auto-refresh
- Confirm dialog before Logout

The HTML is a self-contained SPA with inline CSS and JS (same pattern as current dashboard).

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ccproxy — OAuth Manager</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #0d1117;
      --surface: #161b22;
      --surface2: #21262d;
      --border: #30363d;
      --text: #c9d1d9;
      --text-muted: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warn: #d29922;
      --danger: #f85149;
    }

    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.5;
    }

    header {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 14px 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }

    header h1 { font-size: 18px; font-weight: 600; color: var(--accent); }
    #refresh-status { font-size: 12px; color: var(--text-muted); }

    .container { max-width: 960px; margin: 0 auto; padding: 24px 16px; }

    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }

    .card-header {
      padding: 14px 20px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .card-header h2 { font-size: 15px; font-weight: 600; }

    .badge {
      background: var(--surface2);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 2px 10px;
      font-size: 12px;
      color: var(--text-muted);
    }

    table { width: 100%; border-collapse: collapse; }

    th, td {
      text-align: left;
      padding: 10px 16px;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }

    th {
      font-size: 12px;
      font-weight: 500;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: var(--surface2);
    }

    tr:last-child td { border-bottom: none; }
    tr:hover td { background: rgba(88,166,255,0.04); }

    .chip {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }

    .chip-success { background: rgba(63,185,80,.15); color: var(--success); }
    .chip-warn    { background: rgba(210,153,34,.15); color: var(--warn); }
    .chip-danger  { background: rgba(248,81,73,.15);  color: var(--danger); }
    .chip-muted   { background: var(--surface2); color: var(--text-muted); }

    .empty-row td { text-align: center; color: var(--text-muted); padding: 24px; }

    .actions { display: flex; gap: 6px; }

    .btn {
      padding: 4px 12px;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: var(--surface2);
      color: var(--text);
      font-size: 12px;
      cursor: pointer;
      transition: background 0.15s;
    }

    .btn:hover { background: var(--border); }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-danger { border-color: var(--danger); color: var(--danger); }
    .btn-danger:hover { background: rgba(248,81,73,.15); }
    .btn-accent { border-color: var(--accent); color: var(--accent); }
    .btn-accent:hover { background: rgba(88,166,255,.15); }

    /* Modal */
    .modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.6);
      z-index: 200;
      justify-content: center;
      align-items: center;
    }

    .modal-overlay.active { display: flex; }

    .modal {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      width: 480px;
      max-width: 90vw;
    }

    .modal h3 { margin-bottom: 16px; font-size: 16px; }

    .modal p { color: var(--text-muted); font-size: 13px; margin-bottom: 12px; }

    .modal input[type="text"] {
      width: 100%;
      padding: 8px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      font-size: 14px;
      margin-bottom: 12px;
    }

    .modal input[type="text"]:focus { outline: none; border-color: var(--accent); }

    .modal-actions { display: flex; gap: 8px; justify-content: flex-end; }

    .modal-status {
      font-size: 12px;
      margin-bottom: 12px;
      min-height: 18px;
    }

    .modal-status.error { color: var(--danger); }
    .modal-status.ok { color: var(--success); }

    @media (max-width: 640px) {
      .container { padding: 12px 8px; }
      header { padding: 10px 12px; }
      th, td { padding: 8px 10px; }
    }
  </style>
</head>
<body>

<header>
  <h1>ccproxy OAuth</h1>
  <span id="refresh-status">Loading…</span>
</header>

<div class="container">
  <div class="card">
    <div class="card-header">
      <h2>OAuth Instances</h2>
      <span class="badge" id="instance-count">—</span>
    </div>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Token Status</th>
            <th>Expires At</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="instances-body">
          <tr class="empty-row"><td colspan="4">Loading…</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- Login Modal -->
<div class="modal-overlay" id="login-modal">
  <div class="modal">
    <h3>OAuth Login — <span id="modal-instance"></span></h3>
    <p>A new window will open for Anthropic authorization. After you approve, copy the authorization code and paste it below.</p>
    <div class="modal-status" id="modal-status"></div>
    <input type="text" id="modal-code" placeholder="Paste authorization code here…" />
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">Cancel</button>
      <button class="btn btn-accent" id="modal-submit" onclick="submitCode()">Submit Code</button>
    </div>
  </div>
</div>

<script>
  let currentSessionId = null;

  function esc(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function tokenChip(status) {
    const map = {
      'valid': 'chip-success',
      'expiring soon': 'chip-warn',
      'expired': 'chip-danger',
      'no token': 'chip-muted',
    };
    return `<span class="chip ${map[status] || 'chip-muted'}">${esc(status || '—')}</span>`;
  }

  function fmtExpiry(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString([], { hour12: false, month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' });
  }

  function actionButtons(inst) {
    const name = esc(inst.name);
    let html = '<div class="actions">';
    if (inst.token_status === 'no token') {
      html += `<button class="btn btn-accent" onclick="startLogin('${name}')">Login</button>`;
    } else {
      html += `<button class="btn btn-accent" onclick="startLogin('${name}')">Login</button>`;
      html += `<button class="btn" onclick="doRefresh('${name}')">Refresh</button>`;
      html += `<button class="btn btn-danger" onclick="doLogout('${name}')">Logout</button>`;
    }
    html += '</div>';
    return html;
  }

  function renderInstances(data) {
    document.getElementById('instance-count').textContent = data.length + ' instances';
    const tbody = document.getElementById('instances-body');
    if (!data.length) {
      tbody.innerHTML = '<tr class="empty-row"><td colspan="4">No OAuth instances configured</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(inst => `
      <tr>
        <td><strong>${esc(inst.name)}</strong></td>
        <td>${tokenChip(inst.token_status)}</td>
        <td>${fmtExpiry(inst.token_expires_at)}</td>
        <td>${actionButtons(inst)}</td>
      </tr>
    `).join('');
  }

  async function fetchJSON(url, opts) {
    const res = await fetch(url, opts);
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || `HTTP ${res.status}`);
    return body;
  }

  async function refresh() {
    const el = document.getElementById('refresh-status');
    el.textContent = 'Refreshing…';
    try {
      const data = await fetchJSON('/api/instances');
      renderInstances(data);
      el.textContent = 'Updated ' + new Date().toLocaleTimeString([], { hour12: false });
    } catch (err) {
      el.textContent = 'Error: ' + err.message;
    }
  }

  // --- OAuth Actions ---

  async function startLogin(instanceName) {
    const statusEl = document.getElementById('modal-status');
    const codeInput = document.getElementById('modal-code');
    codeInput.value = '';
    statusEl.textContent = '';
    statusEl.className = 'modal-status';
    document.getElementById('modal-instance').textContent = instanceName;
    document.getElementById('login-modal').classList.add('active');

    try {
      const resp = await fetchJSON('/api/oauth/login/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instance: instanceName }),
      });
      currentSessionId = resp.session_id;
      window.open(resp.authorization_url, '_blank', 'width=600,height=700');
      statusEl.textContent = 'Authorization window opened. Paste the code below after approving.';
    } catch (err) {
      statusEl.textContent = 'Error: ' + err.message;
      statusEl.className = 'modal-status error';
    }
  }

  async function submitCode() {
    const code = document.getElementById('modal-code').value.trim();
    const statusEl = document.getElementById('modal-status');
    if (!code) {
      statusEl.textContent = 'Please paste the authorization code.';
      statusEl.className = 'modal-status error';
      return;
    }

    const btn = document.getElementById('modal-submit');
    btn.disabled = true;
    statusEl.textContent = 'Exchanging code…';
    statusEl.className = 'modal-status';

    try {
      await fetchJSON('/api/oauth/login/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: currentSessionId, code: code }),
      });
      statusEl.textContent = 'Login successful!';
      statusEl.className = 'modal-status ok';
      setTimeout(() => { closeModal(); refresh(); }, 1000);
    } catch (err) {
      statusEl.textContent = 'Error: ' + err.message;
      statusEl.className = 'modal-status error';
    } finally {
      btn.disabled = false;
    }
  }

  function closeModal() {
    document.getElementById('login-modal').classList.remove('active');
    currentSessionId = null;
  }

  async function doRefresh(instanceName) {
    if (!confirm('Force refresh token for ' + instanceName + '?')) return;
    try {
      await fetchJSON('/api/oauth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instance: instanceName }),
      });
      refresh();
    } catch (err) {
      alert('Refresh failed: ' + err.message);
    }
  }

  async function doLogout(instanceName) {
    if (!confirm('Delete token for ' + instanceName + '? This cannot be undone.')) return;
    try {
      await fetchJSON('/api/oauth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ instance: instanceName }),
      });
      refresh();
    } catch (err) {
      alert('Logout failed: ' + err.message);
    }
  }

  // --- Init ---
  refresh();
  setInterval(refresh, 30000);
</script>
</body>
</html>
```

- [ ] **Step 2: Build and verify embed compiles**

Run: `go build ./cmd/ccproxy/`
Expected: compiles successfully

- [ ] **Step 3: Commit**

```bash
git add internal/admin/static/index.html
git commit -m "feat: replace dashboard with OAuth management page"
```

---

### Task 11: Update CLAUDE.md and docs

**Files:**
- Modify: `CLAUDE.md`
- Modify: `config.toml.example` (if not done in Task 6)

- [ ] **Step 1: Update CLAUDE.md**

In the "Configuration" section, remove references to `[[oauth_providers]]` and `oauth_provider`. Update the example config to match the new structure.

In the "OAuth Tokens" section, update: "Token files keyed by instance name (one token per OAuth instance)."

In the "Disguise Engine" section, the activation condition references `instance.IsOAuth()` — no change needed there.

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for instance-based OAuth and removed provider config"
```

---

### Task 12: Final integration test

- [ ] **Step 1: Run full test suite**

Run: `go test ./... -race -count=1`
Expected: ALL PASS

- [ ] **Step 2: Build binary**

Run: `make build`
Expected: compiles successfully

- [ ] **Step 3: Verify config loading**

Run: `./bin/ccproxy test`
Expected: config validates (no errors about missing oauth_providers)

- [ ] **Step 4: Final commit if any remaining changes**

```bash
git status
# If any unstaged changes remain, stage and commit
```
