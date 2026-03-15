# ccproxy

A single-binary Claude API proxy that pools Anthropic OAuth subscription accounts for small team sharing, with full Claude CLI identity impersonation so upstream traffic appears as legitimate Claude Code requests.

## Features

- Full 8-layer Claude CLI impersonation: TLS fingerprint, HTTP headers, anthropic-beta tokens, system prompt injection, metadata.user_id generation, model ID mapping, thinking block cleanup, and body sanitization
- Multi-instance load balancing with session affinity, adaptive backpressure, and load-aware scheduling
- OAuth PKCE flow with encrypted token storage and auto-refresh
- Web-based admin dashboard for instance management and OAuth login
- TOML configuration with auto-generation of missing credentials
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

Configuration is read from `config.toml` (override with `-c <path>`). Changes require a restart to take effect.

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
│   ├── Disguise Engine      8-layer Claude CLI impersonation
│   ├── Load Balancer        L1 Pool throttle → L2 Sticky session → L3 Score selection
│   ├── Concurrency Tracker  Per-instance slot management (in-memory)
│   ├── Budget Controller    Adaptive backpressure with dual-window (5h/7d) tracking
│   ├── OAuth Manager        PKCE flow, AES-256-GCM token storage, auto-refresh
│   └── Observability        Request tracing, metrics, periodic logging
└── Storage Layer
    ├── JSON File            Encrypted OAuth tokens (data/oauth_tokens.json)
    ├── JSON File            Dynamic instance registry (data/instances.json)
    └── TOML File            Configuration (read at startup)
```

**Load balancer** uses a 3-layer selection algorithm:
1. **L1 Pool**: SRE adaptive throttle + utilization-based delay + wait queue
2. **L2 Sticky**: Session affinity (1h TTL) with budget-aware concurrency
3. **L3 Score**: `errorRate*0.3 + latency*0.2 + load*0.2 + utilization*0.3`, lower wins

**Disguise engine** activates when the downstream client is not already a real Claude Code client. It rewrites TLS fingerprint, HTTP headers, anthropic-beta tokens, system prompt, metadata.user_id, and model IDs to match Claude Code traffic patterns.

For detailed architecture documentation, see [docs/architecture.md](docs/architecture.md).

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
