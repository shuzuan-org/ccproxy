# Observability Enhancement Design

## Goal

Extend the existing observability infrastructure to make structured logs a complete window into ccproxy's runtime behavior. Pure log enhancement — no external dependencies, no metrics exporters.

## Approach: Context Logger Unified Propagation

Use `observe.Logger(ctx)` as the single log entry point on all request-path code. Functions that already have `ctx context.Context` replace `slog.XXX` calls with `observe.Logger(ctx).XXX`. Non-request paths (startup, background tasks, shutdown) continue using `slog.XXX` directly.

## 1. Context Propagation

### What changes

Every function on the request path that currently calls `slog.Info/Warn/Error/Debug` directly will switch to `observe.Logger(ctx)`. This ensures every log line carries `request_id` and `api_key` automatically.

### Files affected

| Package | File | Current direct slog calls | Has ctx | Action |
|---------|------|--------------------------|---------|--------|
| loadbalancer | retry.go | ~12 | Yes | Replace with observe.Logger(ctx) |
| loadbalancer | balancer.go | ~4 | Yes | Replace with observe.Logger(ctx) |
| loadbalancer | health.go | ~8 | No → add ctx | Add ctx param, replace with observe.Logger(ctx) |
| loadbalancer | budget.go | ~6 | No → add ctx | Add ctx param, replace with observe.Logger(ctx) |
| loadbalancer | throttle.go | ~3 | Yes | Replace with observe.Logger(ctx) |
| loadbalancer | concurrency.go | ~3 | No (background) | Keep slog (non-request path) |
| oauth | manager.go | ~8 | Partial | Replace where ctx available |
| disguise | engine.go | ~14 | Yes (via *http.Request) | Use req.Context(), replace |
| proxy | handler.go | ~9 | Already uses observe.Logger ✓ | No change needed |
| admin | handler.go | ~16 | No (admin path) | Keep slog (non-request path) |
| config | config.go | ~6 | No (startup) | Keep slog (non-request path) |
| server | server.go | ~8 | No (startup/shutdown) | Keep slog (non-request path) |

### Internal signature changes

These are package-internal methods called on the request path:

- `HealthTracker.RecordResult(instance, statusCode)` → `RecordResult(ctx, instance, statusCode)`
- `BudgetController.UpdateFromHeaders(instance, headers)` → `UpdateFromHeaders(ctx, instance, headers)`
- `BudgetController.Record429(instance, hasResetHeaders)` → `Record429(ctx, instance, hasResetHeaders)`

The callers (retry.go) already have ctx, so these are straightforward additions.

## 2. Missing Key Events

### Request summary log

At the end of every request (success or failure), emit a single Info-level summary:

```
"request completed" request_id=xxx api_key=yyy model=claude-sonnet-4-20250514
  instance=acct-1 status=200 elapsed=1.23s retries=1 failovers=0
  input_tokens=1500 output_tokens=800 stream=true
```

This is the single most valuable log line — it contains everything needed for post-hoc analysis.

### Retry decision path

When the retry loop ends, include `instances_tried` in the summary showing the full path:

```
instances_tried=[acct-1,acct-2,acct-1]
```

### OAuth token expiry warning

In the auto-refresh check loop, when a token has < 10 minutes remaining, emit a Warn:

```
"oauth: token expiring soon" instance=acct-1 expires_in=8m30s
```

### Instance health recovery

When an instance transitions from cooldown back to healthy (cooldown timer expires), emit Info:

```
"instance recovered from cooldown" instance=acct-1 cooldown_duration=30s
```

## 3. Metrics Periodic Summary Enhancement

### Per-instance counters

Add to `observe.Metrics`:

```go
type InstanceMetrics struct {
    RequestsTotal   atomic.Int64
    RequestsSuccess atomic.Int64
    RequestsError   atomic.Int64
    Instances429    atomic.Int64
    Instances529    atomic.Int64
}
```

Stored in a `sync.Map[string, *InstanceMetrics]` keyed by instance name. Lazy-initialized on first access via `Global.Instance(name)`.

### Enhanced periodic output

The 5-minute summary will include:

1. **Global counters** (existing): requests_total, throttled, queued, success, error, retries, failovers, 429s, 529s
2. **Rate**: requests_per_min since last snapshot
3. **Uptime**: process uptime
4. **Per-instance breakdown**: one log line per instance with its counters + current state

Example:

```
"metrics summary" uptime=2h15m requests_total=1500 requests_per_min=5.0
  requests_success=1480 requests_error=20 retries=45 failovers=12

"metrics instance" instance=acct-1 requests=800 success=790 errors=10
  rate_429=3 rate_529=1 state=healthy concurrency=2/5 budget=normal

"metrics instance" instance=acct-2 requests=700 success=690 errors=10
  rate_429=5 rate_529=0 state=cooldown concurrency=0/5 budget=sticky_only
```

### State snapshot integration

The periodic summary queries:
- `HealthTracker` for instance health state (healthy/cooldown/disabled)
- `ConcurrencyTracker` for current slot counts
- `BudgetController` for budget state (Normal/StickyOnly/Blocked)

This requires `StartPeriodicLog` to receive interfaces or callbacks to query these states. Design: pass a `StateProvider` interface:

```go
type StateProvider interface {
    InstanceStates() map[string]InstanceState
}

type InstanceState struct {
    Health      string // "healthy", "cooldown", "disabled"
    Concurrency int    // current active slots
    MaxConcurrency int
    BudgetState string // "normal", "sticky_only", "blocked"
}
```

## 4. What We Are NOT Doing

- No OpenTelemetry or distributed tracing
- No Prometheus/metrics exporters
- No latency histograms
- No per-apikey metrics dimensions
- No component name prefixes on log lines
- No changes to admin dashboard
- No new configuration options (uses existing log_level and log_format)

## 5. Testing Strategy

- Existing tests for `observe/` package to be extended for new InstanceMetrics and StateProvider
- health.go and budget.go tests updated for new ctx parameter
- Integration-style test: verify that a request through the proxy handler produces log lines with request_id correlation (using a custom slog handler that captures output)
