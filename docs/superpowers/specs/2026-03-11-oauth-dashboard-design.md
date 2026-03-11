# OAuth Dashboard Design

Replace the existing admin dashboard with a focused OAuth management page.

## Goals

- Display status of all enabled OAuth instances with their token state
- Provide browser-based OAuth operations: login, refresh, logout
- Simplify config by removing `[[oauth_providers]]` section and hardcoding Anthropic OAuth constants

## Config Changes

### Remove

- `[[oauth_providers]]` section entirely
- `oauth_provider` field from `[[instances]]`

### Before

```toml
[[instances]]
name = "alice-oauth"
auth_mode = "oauth"
oauth_provider = "anthropic"  # REMOVE
...

[[oauth_providers]]            # REMOVE entire section
name = "anthropic"
client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
auth_url = "https://claude.ai/oauth/authorize"
token_url = "https://platform.claude.com/v1/oauth/token"
redirect_uri = "https://platform.claude.com/oauth/code/callback"
scopes = ["org:create_api_key", "user:profile", "user:inference", "user:sessions:claude_code", "user:mcp_servers"]
```

### After

```toml
[[instances]]
name = "alice-oauth"
auth_mode = "oauth"
...
```

Anthropic OAuth constants hardcoded in `internal/oauth/provider.go`:

```go
const (
    ClientID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
    AuthURL     = "https://claude.ai/oauth/authorize"
    TokenURL    = "https://platform.claude.com/v1/oauth/token"
    RedirectURI = "https://platform.claude.com/oauth/code/callback"
    Scopes      = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers"
)
```

## Token Store Change

Current: keyed by provider name (`"anthropic"` → token).

New: keyed by instance name (`"alice-oauth"` → token, `"bob-oauth"` → token). Each OAuth instance has its own independent token representing a distinct Anthropic account.

## Page Design

Single-page dashboard at `/admin/` replacing the existing one. Dark GitHub theme retained.

### OAuth Instances Table

Only shows instances where `auth_mode = "oauth"` and `enabled = true`.

| Name | Token Status | Expires At | Actions |
|---|---|---|---|
| alice-oauth | valid | 2026-03-11 15:30 | [Refresh] [Logout] |
| bob-oauth | expiring soon | 2026-03-11 12:01 | [Refresh] [Logout] |
| carol-oauth | expired | 2026-03-10 08:00 | [Login] [Refresh] [Logout] |
| dave-oauth | no token | — | [Login] |

**Token Status values:**
- `valid` — token exists, not expiring within 5 minutes
- `expiring soon` — token expires within 5 minutes
- `expired` — token past expiry
- `no token` — no token stored for this instance

**Actions button logic:**
- Has token (any state): Refresh + Logout
- No token: Login only

### Login Flow (modal)

1. User clicks [Login] on an instance row
2. Backend generates PKCE verifier/challenge/state, returns authorization URL + session ID
3. Frontend opens `window.open()` to Anthropic authorization page
4. Anthropic page shows authorization code after user approves
5. User copies code, pastes into modal input field
6. Frontend POSTs code + session ID to backend
7. Backend exchanges code for token using stored PKCE verifier, saves to token store keyed by instance name
8. Modal closes, table refreshes

### Auto-refresh

Page polls `/api/instances` every 30 seconds to update the table.

## API Endpoints

All endpoints require admin auth (HTTP Basic Auth if `admin_password` is set).

### GET /api/instances (modified)

Add OAuth token info to response for OAuth instances.

```json
[
  {
    "name": "alice-oauth",
    "auth_mode": "oauth",
    "enabled": true,
    "token_status": "valid",
    "token_expires_at": "2026-03-11T15:30:00Z",
    "load_rate": 40,
    "active_slots": 2,
    "max_concurrency": 5,
    "priority": 1
  }
]
```

### POST /api/oauth/login/start

Start OAuth PKCE flow for an instance.

Request: `{"instance": "alice-oauth"}`

Response:
```json
{
  "authorization_url": "https://claude.ai/oauth/authorize?client_id=...&code_challenge=...&state=...",
  "session_id": "hex-random-id"
}
```

Backend stores `{session_id → verifier, instance_name, state}` in memory with 10-minute TTL.

### POST /api/oauth/login/complete

Complete the OAuth flow by exchanging the authorization code.

Request: `{"session_id": "...", "code": "paste-from-anthropic"}`

Response: `{"ok": true, "expires_at": "2026-03-11T15:30:00Z"}` or error.

Backend looks up session, validates state, calls ExchangeCode with stored verifier, saves token keyed by instance name.

### POST /api/oauth/refresh

Force refresh token for an instance.

Request: `{"instance": "alice-oauth"}`

Response: `{"ok": true, "expires_at": "2026-03-12T15:30:00Z"}` or error.

### POST /api/oauth/logout

Delete token for an instance.

Request: `{"instance": "alice-oauth"}`

Response: `{"ok": true}`

## Signature Changes

### `internal/oauth/provider.go`

```go
// Before: requires config
func NewAnthropicProvider(cfg config.OAuthProviderConfig) *AnthropicProvider

// After: no params, uses package-level constants
func NewAnthropicProvider() *AnthropicProvider
```

### `internal/oauth/manager.go`

```go
// Before: keyed by provider, constructed from OAuthProviderConfig
func NewManager(providers []config.OAuthProviderConfig, store *TokenStore) *Manager
// providers map[string]*AnthropicProvider  (provider name → provider)
// refreshMu map[string]*sync.Mutex         (provider name → mutex)

// After: keyed by instance, constructed from InstanceConfig
func NewManager(instances []config.InstanceConfig, store *TokenStore) *Manager
// instances []config.InstanceConfig         (only oauth instances)
// provider  *AnthropicProvider              (single shared instance, stateless)
// refreshMu map[string]*sync.Mutex          (instance name → mutex)
```

`StartAutoRefresh` iterates over OAuth instance names instead of provider names.
`GetValidToken`, `RefreshToken`, `Status`, `Logout` all take instance name.

### `internal/admin/handler.go`

```go
// Before
func NewHandler(balancer *loadbalancer.Balancer) *Handler

// After: add oauth manager, config, and PKCE session store
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config) *Handler
```

### `internal/oauth/session.go` (new file)

```go
type PKCESession struct {
    InstanceName string
    Verifier     string
    State        string
    CreatedAt    time.Time
}

type SessionStore struct { /* map[sessionID]*PKCESession, sync.Mutex */ }

func NewSessionStore() *SessionStore
func (s *SessionStore) Create(instanceName string) (sessionID, authURL string, err error)
func (s *SessionStore) Complete(sessionID, code string) (string, error) // returns instance name
func (s *SessionStore) StartCleanup(ctx context.Context) // background goroutine, 1-min tick, 10-min TTL
```

`SessionStore` is owned by `admin.Handler`. Cleanup goroutine started in `server.New()` with server context.

### `internal/server/server.go`

```go
// Before
oauthMgr = oauth.NewManager(cfg.OAuthProviders, store)
adminHandler = admin.NewHandler(balancer)

// After
oauthMgr = oauth.NewManager(cfg.Instances, store)
sessions = oauth.NewSessionStore()
sessions.StartCleanup(ctx)
adminHandler = admin.NewHandler(balancer, oauthMgr, sessions, cfg)
```

### `internal/cli/oauth.go`

CLI commands change from `<provider>` to `<instance>` argument. Validate that the given name exists in config as an OAuth instance. `NewAnthropicProvider()` called with no args.

### `internal/config/config.go`

Remove from `Validate()`:
- The `oauthProviders` map construction (lines ~147-151)
- The `inst.OAuthProvider` check against the map (lines ~157-163)

Keep: validation that at least one enabled instance exists.

## Instance Visibility

`GET /api/instances` for the OAuth dashboard reads directly from `config.Instances` (filtered to `auth_mode=oauth`), NOT from `Balancer.GetInstances()`. This ensures disabled OAuth instances remain visible for token management (login/logout).

## Files to Modify

| File | Change |
|---|---|
| `internal/config/config.go` | Remove `OAuthProviderConfig`, `OAuthProviders`, `oauth_provider` from `InstanceConfig`. Remove provider validation from `Validate()`. |
| `internal/oauth/provider.go` | Hardcode constants. `NewAnthropicProvider()` takes no params. |
| `internal/oauth/store.go` | No structural change, keyed by instance name by convention. |
| `internal/oauth/manager.go` | Rewrite: keyed by instance name, single shared provider, new constructor signature. |
| `internal/oauth/session.go` | New file: PKCE session store with auto-cleanup. |
| `internal/admin/handler.go` | New constructor with OAuth deps. Add 4 OAuth endpoints. Modify `HandleInstances` to include token info and read from config directly. |
| `internal/admin/static/index.html` | Replace dashboard with OAuth management page. |
| `internal/server/server.go` | Wire OAuth session store, update `NewManager` and `NewHandler` calls, start cleanup. |
| `internal/cli/oauth.go` | Change arg from provider to instance name. Use `NewAnthropicProvider()`. Validate instance exists. |
| `config.toml.example` | Remove `[[oauth_providers]]` section, remove `oauth_provider` from instances. |

## Security

- All OAuth API endpoints protected by admin auth (same as existing `/api/instances`)
- PKCE session store is in-memory only, 10-minute TTL, auto-cleanup via background goroutine
- Authorization codes and tokens never logged
- Token store remains AES-256-GCM encrypted at rest
