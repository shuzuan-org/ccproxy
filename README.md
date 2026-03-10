# ccproxy

A single-binary Claude API proxy that pools Anthropic OAuth subscription accounts for small team sharing, with full Claude CLI identity impersonation so upstream traffic appears as legitimate Claude Code requests.

## Features

- Full 6-layer Claude CLI impersonation: TLS fingerprint, HTTP headers, anthropic-beta tokens, system prompt injection, metadata.user_id generation, and model ID mapping
- Multi-instance load balancing with session affinity and load-aware scheduling
- OAuth PKCE flow with encrypted token storage and auto-refresh, plus API Key support
- Embedded SQLite for request logging and token usage statistics
- Embedded HTML admin dashboard for monitoring
- TOML configuration with hot-reload (fsnotify + SIGHUP)
- Single binary, no external dependencies

## Quick Start

**Build:**

```bash
make build
# Output: bin/ccproxy
```

**Configure:**

```bash
cp config.toml.example config.toml
# Edit config.toml with your api_keys and instances
```

**Authenticate (OAuth instances only):**

```bash
./bin/ccproxy oauth login anthropic
```

**Run:**

```bash
./bin/ccproxy start
```

The proxy listens on `http://127.0.0.1:3000` by default. Point your Claude-compatible client to this address with one of the configured API keys as the Bearer token.

## Configuration Reference

Configuration is read from `config.toml` (override with `-c <path>`). The file is watched for changes; edits take effect within ~500ms without a restart. You can also send `SIGHUP` to the running process to force a reload.

### `[server]`

| Field | Default | Description |
|-------|---------|-------------|
| `host` | `127.0.0.1` | Listen address |
| `port` | `3000` | Listen port |
| `log_level` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `admin_password` | `""` | Basic-auth password for `/admin/` (empty = no auth) |

### `[[api_keys]]`

Credentials that downstream clients send as `Authorization: Bearer <key>`.

| Field | Description |
|-------|-------------|
| `key` | The bearer token value |
| `name` | Human-readable label used in logs and stats |
| `enabled` | Set to `false` to disable without deleting |

At least one enabled key is required.

### `[[instances]]`

Each instance represents one upstream Anthropic account or API key.

| Field | Default | Description |
|-------|---------|-------------|
| `name` | — | Unique identifier used in logs and stats |
| `auth_mode` | — | `oauth` or `bearer` |
| `oauth_provider` | — | Name of the `[[oauth_providers]]` entry (required when `auth_mode = "oauth"`) |
| `api_key` | — | Anthropic API key (required when `auth_mode = "bearer"`) |
| `priority` | `1` | Lower value = higher priority for load balancer selection |
| `weight` | `100` | Relative weight within the same priority tier |
| `max_concurrency` | `5` | Maximum simultaneous requests for this instance |
| `base_url` | `https://api.anthropic.com` | Upstream API base URL |
| `request_timeout` | `300` | Per-request timeout in seconds |
| `tls_fingerprint` | `false` | Enable Claude CLI TLS fingerprint spoofing (OAuth instances only) |
| `enabled` | `true` | Set to `false` to temporarily disable |

At least one enabled instance is required.

### `[[oauth_providers]]`

OAuth 2.0 PKCE provider definitions. The default Anthropic provider values are already included in `config.toml.example`.

| Field | Description |
|-------|-------------|
| `name` | Unique identifier referenced by `[[instances]]` |
| `client_id` | OAuth application client ID |
| `auth_url` | Authorization endpoint |
| `token_url` | Token exchange endpoint |
| `redirect_uri` | Callback URI (used during the login browser flow) |
| `scopes` | OAuth scopes to request |

### `[observability]`

| Field | Default | Description |
|-------|---------|-------------|
| `retention_days` | `7` | SQLite request log retention period in days |

### Example

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
max_concurrency = 5
tls_fingerprint = true

[[instances]]
name = "bob-apikey"
auth_mode = "bearer"
api_key = "sk-ant-api03-..."
priority = 2
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

## CLI Usage

All commands accept `-c <path>` to specify a config file (default: `config.toml`).

```
ccproxy start               Start the proxy server (foreground)
ccproxy stop                Send SIGTERM to the running server via PID file
ccproxy reload              Send SIGHUP to reload config without restarting
ccproxy test                Validate the config file and exit
ccproxy stats [--hours N]   Print token usage statistics (default: last 24h; 0 = all time)
ccproxy version             Print version

ccproxy oauth login <provider>    Authenticate via browser PKCE flow
ccproxy oauth status              Show token expiry for all stored providers
ccproxy oauth refresh <provider>  Force-refresh the token for a provider
ccproxy oauth logout <provider>   Delete the stored token for a provider
```

The PID file is written to `data/ccproxy.pid` on startup; `stop` and `reload` read it to locate the running process.

## Architecture Overview

```
ccproxy (single binary)
├── CLI Layer (cobra)
│   └── start, stop, reload, test, stats, oauth, version
├── HTTP Server (chi router)
│   ├── /v1/messages         Proxy handler (SSE streaming)
│   ├── /admin/*             Embedded HTML dashboard
│   └── /api/*               Stats and status JSON API
├── Core Services
│   ├── Auth Guard           Bearer token validation (constant-time compare)
│   ├── Proxy Handler        Request forwarding and SSE streaming
│   ├── Disguise Engine      6-layer Claude CLI impersonation
│   ├── Load Balancer        3-layer: sticky session, load-aware, fallback queue
│   ├── Retry Engine         Exponential backoff + instance failover
│   ├── Concurrency Tracker  Per-instance slot management (in-memory sync.Map)
│   └── OAuth Manager        PKCE flow, AES-256-GCM token storage, auto-refresh
└── Storage Layer
    ├── SQLite               Request logs, failover events, token usage stats
    ├── JSON File            AES-256-GCM encrypted OAuth tokens (data/oauth_tokens.json)
    └── TOML File            Configuration with fsnotify hot-reload
```

**Load balancer selection order:**

1. Sticky session (1h TTL) — reuse the same instance for a client session if it has capacity
2. Load-aware selection — filter by load rate, sort by priority then load, shuffle within tiers
3. Fallback queue — wait for any instance to free a slot; timeout returns 503

**Disguise engine** activates only when `auth_mode = "oauth"` and the downstream client is not already a real Claude Code client. It rewrites TLS fingerprint, HTTP headers, anthropic-beta tokens, system prompt, metadata.user_id, and model IDs to match Claude Code 2.x traffic patterns.

## Admin Dashboard

The admin dashboard is served at `http://<host>:<port>/admin/` as an embedded single-page HTML file. It requires no external assets.

If `admin_password` is set in `[server]`, the dashboard and all `/api/*` endpoints are protected by HTTP Basic Auth (any username, the configured password).

Available API endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /admin/` | Dashboard HTML |
| `GET /api/stats?hours=24` | Token usage by instance and time period |
| `GET /api/instances` | Instance health and current load |
| `GET /api/sessions` | Active session list |
| `GET /api/requests?limit=100` | Recent request logs |
