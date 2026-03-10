# ccproxy Design Spec

> Lightweight Claude-to-Claude proxy in Go for small team sharing.

## 1. Overview

ccproxy is a single-binary Claude API proxy that pools Anthropic OAuth subscription accounts (e.g., Claude Code $200/mo) for team sharing. It fully impersonates Claude CLI identity so Anthropic backend sees legitimate Claude Code traffic.

### Goals

- Full 6-layer Claude CLI impersonation (TLS fingerprint, HTTP headers, anthropic-beta, system prompt injection, metadata.user_id generation, model ID mapping)
- Multi-instance load balancing with session affinity and load-aware scheduling
- OAuth PKCE flow + API Key support for backend instances
- Embedded SQLite for request logging and token usage statistics
- Embedded HTML admin dashboard for monitoring
- Single binary, no external dependencies (no Redis, no PostgreSQL)
- TOML configuration with hot-reload

### Non-Goals

- User registration, billing, subscription management
- Multi-platform support (Gemini, OpenAI)
- Telemetry simulation
- Web frontend for user management

## 2. Architecture

```
ccproxy (single binary)
├── CLI Layer (cobra)
│   └── start, stop, reload, test, stats, oauth, version
├── HTTP Server (chi router)
│   ├── /v1/messages → Proxy Handler
│   ├── /admin/* → Embedded Dashboard (embed.FS)
│   └── /api/* → Stats/Status API
├── Core Services
│   ├── Auth Guard — Bearer token validation (constant-time)
│   ├── Proxy Handler — Request forwarding, SSE streaming
│   ├── Disguise Engine — 6-layer Claude CLI impersonation
│   ├── Load Balancer — Session sticky + load-aware selection
│   ├── Retry Engine — Exponential backoff + failover
│   ├── Concurrency Tracker — Per-instance slot management (in-memory)
│   └── OAuth Manager — PKCE flow, encrypted token storage, auto-refresh
└── Storage Layer
    ├── SQLite — Request logs, failover events, token usage
    ├── JSON File — AES-256-GCM encrypted OAuth tokens
    └── TOML File — Configuration with fsnotify hot-reload
```

## 3. Disguise Engine

### 3.1 Trigger Condition

```go
shouldDisguise := instance.IsOAuth() && !isClaudeCodeClient(request)
```

Impersonation only activates when:
1. Backend instance uses OAuth authentication
2. Downstream client is NOT already a real Claude Code client

### 3.2 Six Layers

**Layer 1: TLS Fingerprint**
- Library: `refraction-networking/utls`
- Profile: `claude_cli_v2` (Node.js 20.x + OpenSSL 3.x)
- JA3: `1a28e69016765d92e3b381168d68922c`
- 59 cipher suites, 10 curves, 20 signature algorithms
- Per-instance enable/disable via config

**Layer 2: HTTP Headers**
Updated to match Claude Code 2.1.71 real traffic:
```
User-Agent: claude-cli/2.1.71 (external, cli)
X-Stainless-Lang: js
X-Stainless-Package-Version: 0.74.0
X-Stainless-OS: Linux
X-Stainless-Arch: arm64
X-Stainless-Runtime: node
X-Stainless-Runtime-Version: v24.3.0
X-Stainless-Retry-Count: 0
X-Stainless-Timeout: 600
X-App: cli
Anthropic-Dangerous-Direct-Browser-Access: true
```

**Layer 3: anthropic-beta**
Updated to 2026Q1 real traffic beta tokens:
```
Default (Opus/Sonnet): claude-code-20250219,oauth-2025-04-20,adaptive-thinking-2026-01-28,context-management-2025-06-27,prompt-caching-scope-2026-01-05,effort-2025-11-24
Haiku subagent: interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,claude-code-20250219
count_tokens: claude-code-20250219,oauth-2025-04-20,adaptive-thinking-2026-01-28,token-counting-2024-11-01
API Key (no oauth beta): same as above minus oauth-2025-04-20
```

**Layer 4: System Prompt Injection**
- Inject `"You are Claude Code, Anthropic's official CLI for Claude."` when not present
- Skip injection for Haiku models
- Detect existing Claude Code prompts via prefix matching (6 official variants)

**Layer 5: metadata.user_id Generation**
- Format: `user_{64hex}_account__session_{uuid}`
- `clientID`: `crypto/rand` 32 bytes → hex
- `sessionUUID`: deterministic UUID v4 from session seed

**Layer 6: Model ID Mapping**
```
claude-sonnet-4-5 → claude-sonnet-4-5-20250929
claude-opus-4-5 → claude-opus-4-5-20251101
claude-haiku-4-5 → claude-haiku-4-5-20251001
```
Reverse mapping on responses.

### 3.3 URL Fix
Append `?beta=true` query parameter to upstream URL (matches real traffic).

### 3.4 Claude Code Client Detector
Multi-dimensional validation:
1. User-Agent regex: `^claude-cli/\d+\.\d+\.\d+`
2. X-App header: `cli`
3. anthropic-beta: contains `claude-code-20250219`
4. metadata.user_id: matches `^user_[a-fA-F0-9]{64}_account__session_[\w-]+$`
5. System prompt: Dice coefficient similarity (threshold 0.5) against 6 official variants

## 4. Load Balancer

### 4.1 Multi-Layer Selection (from sub2api)

```
Layer 1: Sticky Session Check (1h TTL)
  → Sticky instance available AND LoadRate < 100 → use it
  → Otherwise continue

Layer 2: Load-Aware Selection
  → Filter instances with LoadRate < 100
  → Sort by Priority → LoadRate → LastUsedAt
  → Shuffle within same tier (avoid thundering herd)
  → Try to acquire slot

Layer 3: Fallback Queue
  → All instances at capacity
  → Wait for lowest-load instance to free a slot
  → Timeout → return 503
```

### 4.2 Concurrency Tracker (in-memory, replaces Redis)

```go
type ConcurrencyTracker struct {
    mu      sync.Mutex
    slots   map[string]map[string]time.Time  // instanceName → {requestID → timestamp}
    waiting map[string]int32                  // instanceName → waiting count
}

LoadRate = (len(slots[name]) + waiting[name]) * 100 / instance.MaxConcurrency
```

Slot TTL: 15 minutes (auto-cleanup of stale entries).

### 4.3 Session Affinity

- Key: `{apiKeyName}:{sessionID}` (sessionID extracted from metadata.user_id)
- Storage: `sync.Map`
- TTL: 1 hour
- On sticky instance failure: clear binding, continue to Layer 2

## 5. Retry & Failover

### 5.1 Retry Strategy (from sub2api)

```go
maxRetryAttempts = 5
retryBaseDelay   = 300ms
retryMaxDelay    = 3s
maxRetryElapsed  = 10s

delay(attempt) = min(retryBaseDelay * 2^(attempt-1), retryMaxDelay)
// 300ms → 600ms → 1.2s → 2.4s → 3s
```

### 5.2 Failover Logic

```
maxAccountSwitches = 10  (max instance switches per request)
maxSameInstanceRetries = 3  (same instance retry limit)
```

| Status Code | Action |
|-------------|--------|
| 400 | Return to client directly (client error) |
| 401/403 | Failover to another instance |
| 429 | Failover immediately (don't wait, switch instance) |
| 529 | Failover |
| 500/502/503/504 | Retry same instance with backoff, then failover |

### 5.3 Upstream Error Response Mapping

```
401 → 502 Bad Gateway ("Upstream authentication failed")
403 → 502 Bad Gateway ("Upstream access forbidden")
429 → 429 Too Many Requests ("Upstream rate limit exceeded")
529 → 503 Service Unavailable ("Upstream service overloaded")
5xx → 502 Bad Gateway ("Upstream service temporarily unavailable")
```

All error responses use Anthropic-style JSON format:
```json
{"type": "error", "error": {"type": "...", "message": "..."}}
```

## 6. OAuth Manager

### 6.1 PKCE Flow
1. Generate verifier (32 bytes, base64url) + challenge (SHA-256)
2. Open browser: `claude.ai/oauth/authorize?...`
3. Local callback server receives authorization code
4. Exchange code + verifier for access_token + refresh_token
5. Store encrypted tokens

### 6.2 Token Storage
- Encryption: AES-256-GCM
- Key derivation: Argon2 from (hostname + username + machine-id)
- File: `data/oauth_tokens.json`, permissions 0600

### 6.3 Auto-Refresh
- Background goroutine every 5 minutes
- Refresh when token expires in < 60 seconds
- Mutex per provider to prevent concurrent refresh

## 7. SSE Streaming

- Read upstream response as byte stream
- Parse `event:` / `data:` lines
- Forward transparently to client
- Extract token usage from `message_delta` events
- Async write to SQLite after stream completes
- Client disconnect detection via context cancellation

## 8. Observability

### 8.1 SQLite Schema

```sql
CREATE TABLE requests (
    request_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    date TEXT NOT NULL,
    hour INTEGER NOT NULL,
    api_key_name TEXT,
    instance_name TEXT,
    model TEXT,
    status TEXT,  -- success|failure|business_error|timeout
    error_type TEXT,
    error_message TEXT,
    input_tokens INTEGER DEFAULT 0,
    output_tokens INTEGER DEFAULT 0,
    cache_creation_input_tokens INTEGER DEFAULT 0,
    cache_read_input_tokens INTEGER DEFAULT 0,
    duration_ms INTEGER,
    session_id TEXT
);

CREATE TABLE failover_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    instance_name TEXT,
    event_type TEXT,
    failure_type TEXT,
    error_message TEXT,
    switch_count INTEGER
);
```

### 8.2 Async Logging
- Buffered channel (10k capacity)
- Background goroutine batch-writes to SQLite
- Auto-cleanup: delete records older than retention_days

## 9. Admin Dashboard

Embedded single HTML page (`embed.FS`) with API endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /admin/` | Dashboard HTML page |
| `GET /api/stats?hours=24` | Token usage stats by instance and time |
| `GET /api/instances` | Instance health status + load info |
| `GET /api/sessions` | Active session list |
| `GET /api/requests?limit=100` | Recent request logs |

Protected by optional `admin_password` in config (basic auth).

## 10. Configuration

```toml
[server]
host = "127.0.0.1"
port = 3000
log_level = "info"
admin_password = ""

[[api_keys]]
key = "sk-ccproxy-001"
name = "dev-team"
enabled = true

[[instances]]
name = "alice-oauth"
auth_mode = "oauth"
oauth_provider = "anthropic"
priority = 1
weight = 100
max_concurrency = 5
base_url = "https://api.anthropic.com"
request_timeout = 300
tls_fingerprint = true

[[instances]]
name = "bob-apikey"
auth_mode = "bearer"
api_key = "sk-ant-api03-..."
priority = 2
weight = 100
max_concurrency = 10

[[oauth_providers]]
name = "anthropic"
client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
auth_url = "https://claude.ai/oauth/authorize"
token_url = "https://console.anthropic.com/v1/oauth/token"
redirect_uri = "https://platform.claude.com/oauth/code/callback"
scopes = ["org:create_api_key", "user:profile", "user:inference"]

[observability]
retention_days = 7
```

Hot-reload via `fsnotify` or `SIGHUP`.

## 11. CLI Commands

```bash
ccproxy start [--daemon]
ccproxy stop
ccproxy reload
ccproxy test              # validate config
ccproxy stats [--hours N]
ccproxy oauth login <provider>
ccproxy oauth status
ccproxy oauth refresh <provider>
ccproxy oauth logout <provider>
ccproxy version
```

## 12. Key Dependencies

| Library | Purpose |
|---------|---------|
| `github.com/go-chi/chi/v5` | HTTP router |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/BurntSushi/toml` | Config parsing |
| `modernc.org/sqlite` | Pure-Go SQLite |
| `github.com/refraction-networking/utls` | TLS fingerprinting |
| `golang.org/x/crypto` | AES-GCM, Argon2 |
| `github.com/fsnotify/fsnotify` | Config file watching |
| `github.com/google/uuid` | UUID generation |

## 13. Project Structure

```
ccproxy/
├── cmd/ccproxy/main.go
├── internal/
│   ├── config/config.go
│   ├── server/server.go
│   ├── proxy/
│   │   ├── handler.go
│   │   └── streaming.go
│   ├── auth/middleware.go
│   ├── disguise/
│   │   ├── engine.go
│   │   ├── headers.go
│   │   ├── beta.go
│   │   ├── metadata.go
│   │   ├── models.go
│   │   └── detector.go
│   ├── loadbalancer/
│   │   ├── balancer.go
│   │   ├── concurrency.go
│   │   └── retry.go
│   ├── oauth/
│   │   ├── manager.go
│   │   ├── provider.go
│   │   ├── store.go
│   │   └── pkce.go
│   ├── tls/fingerprint.go
│   ├── observability/
│   │   ├── logger.go
│   │   └── stats.go
│   ├── admin/
│   │   ├── handler.go
│   │   └── static/index.html
│   └── session/session.go
├── migrations/001_init.sql
├── data/  (.gitignore)
├── config.toml.example
├── go.mod
└── Makefile
```
