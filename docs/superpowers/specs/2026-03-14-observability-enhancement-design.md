# Observability Enhancement Design

## Goal

Extend the existing observability infrastructure to make structured logs a complete window into ccproxy's runtime behavior. Pure log enhancement — no external dependencies, no metrics exporters.

## Approach: Context Logger Unified Propagation

Use `observe.Logger(ctx)` as the single log entry point on all request-path code. Functions that already have `ctx context.Context` replace `slog.XXX` calls with `observe.Logger(ctx).XXX`. Non-request paths (startup, background tasks, shutdown) continue using `slog.XXX` directly.

## 1. Context Propagation

### What changes

Every function on the request path that currently calls `slog.Info/Warn/Error/Debug` directly will switch to `observe.Logger(ctx)`. This ensures every log line carries `request_id` and `api_key` automatically.

### Files affected

| Package | File | Has ctx | Action |
|---------|------|---------|--------|
| loadbalancer | retry.go | Yes | Replace slog calls with observe.Logger(ctx) |
| loadbalancer | balancer.go | Yes | Replace slog calls with observe.Logger(ctx) |
| loadbalancer | health.go | No → add ctx | Add ctx param to RecordSuccess/RecordError, replace |
| loadbalancer | budget.go | No → add ctx | Add ctx param to UpdateFromHeaders/Record429, replace |
| loadbalancer | throttle.go | Yes | Replace slog calls with observe.Logger(ctx) |
| loadbalancer | usage.go | Yes | Replace slog calls with observe.Logger(ctx) |
| loadbalancer | concurrency.go | No (background) | Keep slog (non-request path) |
| oauth | manager.go | Partial | Replace where ctx available |
| disguise | engine.go | Yes (via *http.Request) | Use req.Context(), replace |
| proxy | handler.go | Yes | Already uses observe.Logger for some; extend to doRequest() |
| proxy | streaming.go | Yes | Replace slog calls with observe.Logger(ctx) |
| admin | handler.go | No (admin path) | Keep slog (non-request path) |
| config | config.go | No (startup) | Keep slog (non-request path) |
| server | server.go | No (startup/shutdown) | Keep slog (non-request path) |

### Internal signature changes

These are package-internal methods called on the request path. Note: `AccountHealth` methods are per-account (no account param needed), and `BudgetController` is per-account (no account param needed). Only ctx is added.

- `AccountHealth.RecordSuccess()` → `RecordSuccess(ctx context.Context)`
- `AccountHealth.RecordError(statusCode int)` → `RecordError(ctx context.Context, statusCode int)`
- `BudgetController.UpdateFromHeaders(headers http.Header)` → `UpdateFromHeaders(ctx context.Context, headers http.Header)`
- `BudgetController.Record429(hasResetHeaders bool)` → `Record429(ctx context.Context, hasResetHeaders bool)`

The callers (retry.go, balancer.go) already have ctx. The `Balancer.ReportResult` method that calls `AccountHealth.RecordSuccess/RecordError` will also need ctx added to its signature.

## 2. Missing Key Events

### Request summary log

At the end of every request, emit a single summary log with level determined by outcome:

| Scenario | Level | Condition |
|----------|-------|-----------|
| Clean success | Debug | status 2xx, no retries, no failovers |
| Success with retries/failover | Info | status 2xx, retries > 0 or failovers > 0 |
| Failure | Warn | all non-2xx final results |

```
"request completed" request_id=xxx api_key=yyy model=claude-sonnet-4-20250514
  account=acct-1 status=200 elapsed=1.23s retries=1 failovers=0
  input_tokens=1500 output_tokens=800 stream=true
```

At default `info` level, only "eventful" and failed requests appear. Switch to `debug` for the full picture.

### Retry decision path

When the retry loop ends, include `accounts_tried` in the summary showing the full path:

```
accounts_tried=[acct-1,acct-2,acct-1]
```

### OAuth token expiry warning

In the auto-refresh check loop, when a token has < 2 minutes remaining (aligned with the 60s refresh threshold, providing one extra ticker interval of advance warning), emit a Warn:

```
"oauth: token expiring soon" account=acct-1 expires_in=90s
```

### Account health recovery

When an account transitions from cooldown back to healthy, emit Info. Implementation: add a `wasCoolingDown` flag to `AccountHealth`. When `IsAvailable()` is called and `time.Now().After(cooldownUntil)` transitions from false to true (i.e., `wasCoolingDown` was set), log the recovery and clear the flag.

```
"account recovered from cooldown" account=acct-1 cooldown_duration=30s
```

## 3. Metrics Periodic Summary Enhancement

### Per-account counters

Add to `observe.Metrics`:

```go
type AccountMetrics struct {
    RequestsTotal   atomic.Int64
    RequestsSuccess atomic.Int64
    RequestsError   atomic.Int64
    Errors429       atomic.Int64
    Errors529       atomic.Int64
}
```

Stored in a `sync.Map` keyed by account name. Lazy-initialized on first access via `Global.Account(name)`.

### Enhanced periodic output

The 5-minute summary will include:

1. **Global counters** (existing): requests_total, throttled, queued, success, error, retries, failovers, 429s, 529s
2. **Rate**: requests_per_min since last snapshot
3. **Uptime**: process uptime
4. **Per-account breakdown**: one log line per account with its counters + current state

Example:

```
"metrics summary" uptime=2h15m requests_total=1500 requests_per_min=5.0
  requests_success=1480 requests_error=20 retries=45 failovers=12

"metrics account" account=acct-1 requests=800 success=790 errors=10
  errors_429=3 errors_529=1 state=healthy concurrency=2/5 budget=normal

"metrics account" account=acct-2 requests=700 success=690 errors=10
  errors_429=5 errors_529=0 state=cooldown concurrency=0/5 budget=sticky_only
```

### State snapshot integration

The periodic summary queries:
- `HealthTracker` for account health state (healthy/cooldown/disabled)
- `ConcurrencyTracker` for current slot counts
- `BudgetController` for budget state (Normal/StickyOnly/Blocked)

This requires `StartPeriodicLog` to receive interfaces or callbacks to query these states. Design: pass a `StateProvider` interface:

```go
type StateProvider interface {
    AccountStates() map[string]AccountState
}

type AccountState struct {
    Health         string // "healthy", "cooldown", "disabled"
    Concurrency    int    // current active slots
    MaxConcurrency int
    BudgetState    string // "normal", "sticky_only", "blocked"
}
```

The `Balancer` struct implements `StateProvider` since it already holds references to HealthTracker, ConcurrencyTracker, and BudgetController.

## 4. What We Are NOT Doing

- No OpenTelemetry or distributed tracing
- No Prometheus/metrics exporters
- No latency histograms
- No per-apikey metrics dimensions
- No component name prefixes on log lines
- No changes to admin dashboard
- No new configuration options (uses existing log_level and log_format)

## 5. Testing Strategy

- Existing tests for `observe/` package to be extended for new AccountMetrics and StateProvider
- health.go and budget.go tests updated for new ctx parameter
- Integration-style test: verify that a request through the proxy handler produces log lines with request_id correlation (using a custom slog handler that captures output)
