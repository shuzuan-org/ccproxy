# ccproxy — Claude Code Development Guide

## Project Overview

ccproxy is a single-binary Claude API proxy written in Go. It pools Anthropic OAuth subscription accounts for team sharing and impersonates Claude CLI identity at six layers (TLS fingerprint, HTTP headers, beta tokens, system prompt, metadata.user_id, model mapping).

Module path: `github.com/binn/ccproxy`

For detailed architecture documentation, see [docs/architecture.md](docs/architecture.md).

## Build Commands

```bash
make build          # Compile to bin/ccproxy
make test           # Run all tests with -race
make run            # Build then run: ./bin/ccproxy
make clean          # Remove bin/ and data/
```

Embed a version string at build time:

```bash
VERSION=1.0.0 make build
```

Run a single package:

```bash
go test ./internal/disguise/... -v -race
```

## Key Directories

```
cmd/ccproxy/        Entry point (main.go)
internal/
  admin/            Embedded HTML dashboard handler and static assets
  apierror/         Shared API error types
  auth/             Bearer token validation middleware (constant-time compare)
  cli/              Cobra commands: root (start), version
  config/           TOML config loading, validation, defaults, instance registry
  disguise/         6-layer Claude CLI impersonation engine
  fileutil/         File I/O helpers (atomic write, etc.)
  loadbalancer/     3-layer balancer, concurrency tracker, retry/failover, budget, health, usage
  netutil/          SOCKS5 proxy support
  oauth/            PKCE flow, AES-256-GCM token store, session store, Anthropic provider
  observe/          Request tracing context and metrics
  proxy/            HTTP proxy handler, SSE streaming, body filter, error mapping
  ratelimit/        Per-IP rate limiting middleware
  server/           HTTP server setup (net/http mux, middleware wiring)
  session/          Session affinity with TTL management
  tls/              TLS fingerprint spoofing
data/               Runtime data — NOT committed (.gitignore)
  instances.json    Dynamic instance registry (0600)
  oauth_tokens.json Encrypted OAuth tokens (0600)
config.toml.example Reference configuration
```

## Important Patterns

### Error Handling

- Always wrap errors with `fmt.Errorf("context: %w", err)` to preserve the chain.
- CLI commands return `error`; cobra prints it and exits non-zero automatically.
- HTTP handlers use `internal/proxy/errors.go` helpers to produce Anthropic-style JSON error bodies.

### Configuration

- `config.Load(path)` reads, parses, applies defaults, auto-generates missing credentials, and validates in one call.
- If `admin_password` is empty or `api_keys` has no enabled entries, `Load` auto-generates cryptographically secure values, persists them to the config file, and prints them to the console.
- `base_url`, `request_timeout`, `max_concurrency` are global settings under `[server]`.
- Instances are **not** defined in TOML. They are managed dynamically via the admin dashboard ("Add Claude" / "Remove" buttons) and persisted to `data/instances.json` by `config.InstanceRegistry`.
- `config.RuntimeInstance(inst)` and `config.RuntimeInstances(registry)` build `InstanceConfig` structs from global settings + registry entries for downstream consumers (balancer, proxy, oauth).
- `InstanceRegistry.SetOnChange(fn)` propagates dynamic add/remove to balancer and OAuth manager at runtime.

### Concurrency

- `ConcurrencyTracker` in `internal/loadbalancer/concurrency.go` uses `sync.Mutex` and a `map[instanceName]map[requestID]time.Time` for slot tracking. No Redis.
- Session affinity uses `sync.Map` with `{apiKeyName}:{sessionID}` keys and 1h TTL.
- OAuth token store uses per-instance mutexes to prevent concurrent refresh races.

### Disguise Engine

Activation condition: `!isClaudeCodeClient(request)`. All instances use OAuth; disguise is always applied for non-Claude Code clients. TLS fingerprint is always enabled.

The `isClaudeCodeClient` detector in `internal/disguise/detector.go` checks five dimensions (User-Agent, X-App, anthropic-beta, metadata.user_id pattern, system prompt Dice coefficient). All five must pass before a request is considered native Claude Code traffic.

### OAuth

All instances use OAuth authentication. Anthropic OAuth constants (ClientID, AuthURL, TokenURL, RedirectURI, Scopes) are hardcoded in `internal/oauth/provider.go`.

Tokens are stored per-instance (not per-provider) at `data/oauth_tokens.json` with 0600 permissions. Encryption key is derived via Argon2 from `hostname + username + machine-id` — no passphrase is ever stored. Never log or return raw token values.

The admin dashboard at `/admin/` provides a web UI for OAuth instance management: add instance, remove instance, login (PKCE flow with manual code paste), refresh, and logout. PKCE sessions are stored in-memory with 10-minute TTL. Instance add/remove triggers `InstanceRegistry.onChange` which updates the balancer and OAuth manager dynamically.

### SSE Streaming

The proxy forwards the upstream response as a raw byte stream. Token usage is extracted from `message_delta` events during streaming.

## Testing Approach

- TDD: write the test first, then implement until it passes.
- Every non-trivial package has a `*_test.go` file in the same package (white-box) or `*_test` package (black-box).
- Table-driven tests using `t.Run(name, ...)` for multiple input variants.
- Use `t.Parallel()` in unit tests that have no shared mutable state.
- The `-race` flag is mandatory; all CI runs use it.

## Config File During Development

Copy and edit `config.toml.example`:

```bash
cp config.toml.example config.toml
```

Then run:

```bash
make run
```
