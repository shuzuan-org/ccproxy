# ccproxy — Claude Code Development Guide

## Project Overview

ccproxy is a single-binary Claude API proxy written in Go. It pools Anthropic OAuth subscription accounts for team sharing and impersonates Claude CLI identity at six layers (TLS fingerprint, HTTP headers, beta tokens, system prompt, metadata.user_id, model mapping). See `docs/superpowers/specs/2026-03-10-ccproxy-design.md` for the full design spec.

Module path: `github.com/binn/ccproxy`

## Build Commands

```bash
make build          # Compile to bin/ccproxy
make test           # Run all tests with -race
make run            # Build then run: ./bin/ccproxy start
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
  auth/             Bearer token validation middleware (constant-time compare)
  admin/            Embedded HTML dashboard handler and static assets
  cli/              Cobra commands: start, stop, reload, test, oauth, version
  config/           TOML config loading, validation, defaults, fsnotify hot-reload
  disguise/         6-layer Claude CLI impersonation engine
  loadbalancer/     3-layer balancer, concurrency tracker, retry/failover engine
  oauth/            PKCE flow, AES-256-GCM token store, Anthropic provider
  proxy/            HTTP proxy handler, SSE streaming, error mapping
  server/           HTTP server setup (net/http mux, middleware wiring)
data/               Runtime data — NOT committed (.gitignore)
  ccproxy.pid       PID file written by `start`, read by `stop`/`reload`
  oauth_tokens.json Encrypted OAuth tokens (0600)
docs/               Design specs and notes
config.toml.example Reference configuration
```

## Important Patterns

### Error Handling

- Always wrap errors with `fmt.Errorf("context: %w", err)` to preserve the chain.
- CLI commands return `error`; cobra prints it and exits non-zero automatically.
- HTTP handlers use `internal/proxy/errors.go` helpers to produce Anthropic-style JSON error bodies.

### Configuration

- `config.Load(path)` reads, parses, applies defaults, and validates in one call.
- `config.Watch(path, callback)` starts a background fsnotify watcher with 500ms debounce.
- The `[[instances]]` `enabled` field is a `*bool` so that nil = default-true is distinguishable from explicit false.

### Concurrency

- `ConcurrencyTracker` in `internal/loadbalancer/concurrency.go` uses `sync.Mutex` and a `map[instanceName]map[requestID]time.Time` for slot tracking. No Redis.
- Session affinity uses `sync.Map` with `{apiKeyName}:{sessionID}` keys and 1h TTL.
- OAuth token store uses per-provider mutexes to prevent concurrent refresh races.

### Disguise Engine

Activation condition: `instance.IsOAuth() && !isClaudeCodeClient(request)`. Do not apply disguise to API-key instances or to real Claude Code clients.

The `isClaudeCodeClient` detector in `internal/disguise/detector.go` checks five dimensions (User-Agent, X-App, anthropic-beta, metadata.user_id pattern, system prompt Dice coefficient). All five must pass before a request is considered native Claude Code traffic.

### OAuth Tokens

Token files are stored at `data/oauth_tokens.json` with 0600 permissions. Encryption key is derived via Argon2 from `hostname + username + machine-id` — no passphrase is ever stored. Never log or return raw token values.

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

Validate before starting:

```bash
./bin/ccproxy test
```
