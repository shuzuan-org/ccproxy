# ccproxy

A single-binary Claude API proxy that pools Anthropic OAuth subscription accounts for small team sharing, with full Claude CLI identity impersonation so upstream traffic appears as legitimate Claude Code requests.

## Features

- Full 6-layer Claude CLI impersonation: TLS fingerprint, HTTP headers, anthropic-beta tokens, system prompt injection, metadata.user_id generation, and model ID mapping
- Multi-instance load balancing with session affinity, adaptive backpressure, and load-aware scheduling
- OAuth PKCE flow with encrypted token storage and auto-refresh
- Web-based admin dashboard for instance management and OAuth login
- TOML configuration with hot-reload (fsnotify)
- Observability: request tracing, metrics, and periodic logging
- Single binary, no external dependencies

## Quick Start

**Build:**

```bash
make build
# Output: bin/ccproxy
```

**Run:**

```bash
./bin/ccproxy
```

On first start, ccproxy auto-generates a `config.toml` (if missing), an API key, and an admin password, then prints them to the console.

**Add instances:** Open `http://<host>:<port>/admin/` and use the "Add Claude" button. Authenticate each instance via the OAuth login flow in the dashboard.

The proxy listens on `http://0.0.0.0:3000` by default. Point your Claude-compatible client to this address with the generated API key as the Bearer token.

## Configuration Reference

Configuration is read from `config.toml` (override with `-c <path>`). The file is watched for changes; edits take effect within ~500ms without a restart.

### `[server]`

| Field | Default | Description |
|-------|---------|-------------|
| `host` | `0.0.0.0` | Listen address |
| `port` | `3000` | Listen port |
| `admin_password` | (auto-generated) | Basic-auth password for `/admin/` and `/api/*` routes |
| `rate_limit` | `60` | Max requests per minute per IP for admin routes |
| `base_url` | `https://api.anthropic.com` | Upstream Anthropic API base URL |
| `request_timeout` | `300` | Per-request timeout in seconds |
| `max_concurrency` | `5` | Per-instance concurrency limit |
| `log_level` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |
| `log_format` | `text` | Log format (`text` or `json`) |

### `[[api_keys]]`

Credentials that downstream clients send as `Authorization: Bearer <key>`.

| Field | Description |
|-------|-------------|
| `key` | The bearer token value |
| `name` | Human-readable label used in logs |
| `enabled` | Set to `false` to disable without deleting |

If no enabled key is configured, one is auto-generated on startup.

### Instances

Instances are **not** defined in the TOML config file. They are managed dynamically via the admin dashboard ("Add Claude" / "Remove" buttons) and persisted to `data/instances.json`.

### Example

```toml
[server]
host = "0.0.0.0"
port = 3000
base_url = "https://api.anthropic.com"
request_timeout = 300
max_concurrency = 5

[[api_keys]]
key = "sk-ccproxy-001"
name = "dev-team"
enabled = true
```

## CLI Usage

```
ccproxy                   Start the proxy server (foreground)
ccproxy version           Print version
ccproxy -c <path>         Use a specific config file (default: config.toml)
```

## Architecture Overview

```
ccproxy (single binary)
├── CLI Layer (cobra)
│   └── start (root command), version
├── HTTP Server (net/http ServeMux)
│   ├── /v1/messages         Proxy handler (SSE streaming)
│   ├── /admin/              Embedded HTML dashboard
│   ├── /api/*               Instance management and OAuth API
│   └── /health              Health check
├── Core Services
│   ├── Auth Guard           Bearer token validation (constant-time compare)
│   ├── Rate Limiter         Per-IP rate limiting for admin routes
│   ├── Proxy Handler        Request forwarding and SSE streaming
│   ├── Disguise Engine      6-layer Claude CLI impersonation
│   ├── Load Balancer        Session affinity → load-aware → fallback queue
│   ├── Concurrency Tracker  Per-instance slot management (in-memory)
│   ├── Budget Controller    Adaptive backpressure with dual-window tracking
│   ├── OAuth Manager        PKCE flow, AES-256-GCM token storage, auto-refresh
│   └── Observability        Request tracing, metrics, periodic logging
└── Storage Layer
    ├── JSON File            Encrypted OAuth tokens (data/oauth_tokens.json)
    ├── JSON File            Dynamic instance registry (data/instances.json)
    └── TOML File            Configuration with fsnotify hot-reload
```

**Load balancer selection order:**

1. Sticky session (1h TTL) — reuse the same instance for a client session if it has capacity
2. Load-aware selection — filter by load rate, sort by priority then load, shuffle within tiers
3. Fallback queue — wait for any instance to free a slot; timeout returns 503

**Disguise engine** activates when the downstream client is not already a real Claude Code client. It rewrites TLS fingerprint, HTTP headers, anthropic-beta tokens, system prompt, metadata.user_id, and model IDs to match Claude Code traffic patterns.

## Admin Dashboard

The admin dashboard is served at `http://<host>:<port>/admin/` as an embedded single-page HTML file. It requires no external assets.

The dashboard and all `/api/*` endpoints are protected by HTTP Basic Auth (any username, the configured admin password).

Available API endpoints:

| Endpoint | Description |
|----------|-------------|
| `GET /admin/` | Dashboard HTML |
| `GET /api/instances` | Instance list with health and load |
| `POST /api/instances/add` | Add a new instance |
| `POST /api/instances/remove` | Remove an instance |
| `POST /api/instances/proxy` | Update instance proxy setting |
| `GET /api/sessions` | Active session list |
| `POST /api/oauth/login/start` | Start OAuth PKCE login flow |
| `POST /api/oauth/login/complete` | Complete OAuth login with auth code |
| `POST /api/oauth/refresh` | Force-refresh an instance's token |
| `POST /api/oauth/logout` | Revoke and delete an instance's token |
