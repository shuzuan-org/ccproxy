# Observability Enhancement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend structured logging across the entire ccproxy project so every request-path log line carries request context (request_id, api_key), add missing key events, and enhance periodic metrics with per-account breakdown and runtime state snapshots.

**Architecture:** Replace direct `slog.XXX` calls with `observe.Logger(ctx).XXX` on all request-path code. Add `ctx context.Context` parameter to internal functions that lack it (health, budget, disguise). Enhance `observe.Metrics` with per-account counters, rate calculation, and a `StateProvider` interface for runtime state snapshots.

**Tech Stack:** Go stdlib (`log/slog`, `sync`, `sync/atomic`), existing `internal/observe` package

**Spec:** `docs/superpowers/specs/2026-03-14-observability-enhancement-design.md`

---

## File Structure

### Modified files

| File | Changes |
|------|---------|
| `internal/observe/metrics.go` | Add AccountMetrics, StateProvider, enhanced StartPeriodicLog |
| `internal/observe/metrics_test.go` | Tests for above |
| `internal/loadbalancer/health.go` | Add ctx to RecordSuccess/RecordError/RecordTimeout, wasCoolingDown recovery log |
| `internal/loadbalancer/health_test.go` | Update for ctx |
| `internal/loadbalancer/budget.go` | Add ctx to UpdateFromHeaders/Record429/RecordSuccess/checkStateChange |
| `internal/loadbalancer/budget_test.go` | Update for ctx |
| `internal/loadbalancer/balancer.go` | Add ctx to ReportResult, implement StateProvider, replace slog |
| `internal/loadbalancer/balancer_test.go` | Update for ctx |
| `internal/loadbalancer/retry.go` | Replace slog with observe.Logger(ctx), track accounts_tried |
| `internal/loadbalancer/retry_test.go` | Update if needed |
| `internal/loadbalancer/throttle.go` | Replace slog where ctx available |
| `internal/loadbalancer/usage.go` | Replace slog with observe.Logger(ctx) |
| `internal/disguise/engine.go` | Use origReq.Context() for observe.Logger |
| `internal/oauth/manager.go` | Replace slog where ctx available, token expiry warning |
| `internal/proxy/handler.go` | Replace remaining slog in doRequest(), add request summary log |
| `internal/proxy/streaming.go` | Replace slog with observe.Logger(ctx) |
| `internal/server/server.go` | Wire StateProvider into StartPeriodicLog |

---

## Chunk 1: observe Package Enhancements

### Task 1: Add AccountMetrics to observe package

**Files:**
- Modify: `internal/observe/metrics.go`
- Modify: `internal/observe/metrics_test.go`

- [ ] **Step 1: Write failing test for AccountMetrics**

In `internal/observe/metrics_test.go`, add:

```go
func TestAccountMetrics(t *testing.T) {
	t.Parallel()
	m := &Metrics{}

	im1 := m.Account("acct-1")
	if im1 == nil {
		t.Fatal("Account returned nil")
	}

	// Same pointer on repeated access
	im2 := m.Account("acct-1")
	if im1 != im2 {
		t.Fatal("Account returned different pointer for same name")
	}

	// Different account returns different pointer
	im3 := m.Account("acct-2")
	if im1 == im3 {
		t.Fatal("Different accounts returned same pointer")
	}

	im1.RequestsTotal.Add(5)
	im1.RequestsSuccess.Add(3)
	im1.RequestsError.Add(2)
	im1.Errors429.Add(1)
	im1.Errors529.Add(1)

	if im1.RequestsTotal.Load() != 5 {
		t.Fatalf("expected 5, got %d", im1.RequestsTotal.Load())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/observe/... -run TestAccountMetrics -v`
Expected: FAIL (Account method not defined)

- [ ] **Step 3: Implement AccountMetrics**

In `internal/observe/metrics.go`, add the `accounts sync.Map` field to `Metrics` struct, and add:

```go
// AccountMetrics tracks per-account counters.
type AccountMetrics struct {
	RequestsTotal   atomic.Int64
	RequestsSuccess atomic.Int64
	RequestsError   atomic.Int64
	Errors429       atomic.Int64
	Errors529       atomic.Int64
}

// Account returns the per-account metrics for the given name, lazily initialized.
func (m *Metrics) Account(name string) *AccountMetrics {
	if v, ok := m.accounts.Load(name); ok {
		return v.(*AccountMetrics)
	}
	im := &AccountMetrics{}
	actual, _ := m.accounts.LoadOrStore(name, im)
	return actual.(*AccountMetrics)
}
```

Add `"sync"` to imports. Add the field:
```go
type Metrics struct {
	// ... existing fields ...
	accounts sync.Map // accountName → *AccountMetrics
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/observe/... -run TestAccountMetrics -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/observe/metrics.go internal/observe/metrics_test.go
git commit -m "feat(observe): add per-account metrics counters"
```

### Task 2: Add StateProvider interface and enhanced periodic logging

**Files:**
- Modify: `internal/observe/metrics.go`
- Modify: `internal/observe/metrics_test.go`

- [ ] **Step 1: Write failing test for enhanced periodic log**

In `internal/observe/metrics_test.go`, add:

```go
func TestStartPeriodicLogWithState(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	m := &Metrics{}
	m.RequestsTotal.Store(100)
	m.RequestsSuccess.Store(95)
	m.Account("acct-1").RequestsTotal.Store(60)
	m.Account("acct-2").RequestsTotal.Store(40)

	provider := &mockStateProvider{
		states: map[string]AccountState{
			"acct-1": {Health: "healthy", Concurrency: 2, MaxConcurrency: 5, BudgetState: "normal"},
			"acct-2": {Health: "cooldown", Concurrency: 0, MaxConcurrency: 5, BudgetState: "sticky_only"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.StartPeriodicLog(ctx, 50*time.Millisecond, provider, logger)
	time.Sleep(80 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	output := buf.String()
	if !strings.Contains(output, "metrics summary") {
		t.Errorf("missing 'metrics summary' in output:\n%s", output)
	}
	if !strings.Contains(output, "requests_per_min") {
		t.Errorf("missing 'requests_per_min' in output:\n%s", output)
	}
	if !strings.Contains(output, "metrics account") {
		t.Errorf("missing 'metrics account' in output:\n%s", output)
	}
}

type mockStateProvider struct {
	states map[string]AccountState
}

func (m *mockStateProvider) AccountStates() map[string]AccountState {
	return m.states
}
```

Add `"bytes"`, `"log/slog"`, `"strings"` to imports.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/observe/... -run TestStartPeriodicLogWithState -v`
Expected: FAIL (signature mismatch or missing types)

- [ ] **Step 3: Implement StateProvider and enhanced StartPeriodicLog**

In `internal/observe/metrics.go`:

Add types:
```go
// StateProvider supplies runtime state for periodic metrics snapshots.
type StateProvider interface {
	AccountStates() map[string]AccountState
}

// AccountState represents the runtime state of a single account.
type AccountState struct {
	Health         string
	Concurrency    int
	MaxConcurrency int
	BudgetState    string
}
```

Update `StartPeriodicLog` signature and body:
```go
// StartPeriodicLog starts a goroutine that logs a metrics snapshot every interval.
// If state is non-nil, also logs per-account state. If logger is nil, uses slog.Default().
// It stops when ctx is cancelled.
func (m *Metrics) StartPeriodicLog(ctx context.Context, interval time.Duration, state StateProvider, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	startTime := time.Now()
	var lastTotal int64
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := m.Snapshot()
				currentTotal := snap["requests_total"]
				elapsed := time.Since(startTime)
				rate := float64(currentTotal-lastTotal) / interval.Minutes()
				lastTotal = currentTotal

				logger.Info("metrics summary",
					"uptime", elapsed.Round(time.Second).String(),
					"requests_total", snap["requests_total"],
					"requests_per_min", fmt.Sprintf("%.1f", rate),
					"requests_success", snap["requests_success"],
					"requests_error", snap["requests_error"],
					"requests_throttled", snap["requests_throttled"],
					"requests_queued", snap["requests_queued"],
					"retries_total", snap["retries_total"],
					"failovers_total", snap["failovers_total"],
					"accounts_429", snap["accounts_429"],
					"accounts_529", snap["accounts_529"],
				)

				if state != nil {
					for name, is := range state.AccountStates() {
						im := m.Account(name)
						logger.Info("metrics account",
							"account", name,
							"requests", im.RequestsTotal.Load(),
							"success", im.RequestsSuccess.Load(),
							"errors", im.RequestsError.Load(),
							"errors_429", im.Errors429.Load(),
							"errors_529", im.Errors529.Load(),
							"state", is.Health,
							"concurrency", fmt.Sprintf("%d/%d", is.Concurrency, is.MaxConcurrency),
							"budget", is.BudgetState,
						)
					}
				}
			}
		}
	}()
}
```

Add `"fmt"` to imports.

- [ ] **Step 4: Update existing TestMetrics_StartPeriodicLog**

The existing test at `metrics_test.go:90` calls `m.StartPeriodicLog(ctx, 10*time.Millisecond)` with old signature. Update to:
```go
m.StartPeriodicLog(ctx, 10*time.Millisecond, nil, nil)
```

- [ ] **Step 5: Run all observe tests**

Run: `go test ./internal/observe/... -v -race`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add internal/observe/metrics.go internal/observe/metrics_test.go
git commit -m "feat(observe): add StateProvider and enhanced periodic logging"
```

---

## Chunk 2: loadbalancer Context Propagation (Atomic)

**Important:** Tasks 3-6 form an atomic unit. All signature changes and their callers must be updated together to maintain compilability. Commit after all changes compile.

### Task 3: Add ctx to health.go, budget.go, balancer.go, and retry.go simultaneously

**Files:**
- Modify: `internal/loadbalancer/health.go`
- Modify: `internal/loadbalancer/health_test.go`
- Modify: `internal/loadbalancer/budget.go`
- Modify: `internal/loadbalancer/budget_test.go`
- Modify: `internal/loadbalancer/balancer.go`
- Modify: `internal/loadbalancer/balancer_test.go`
- Modify: `internal/loadbalancer/retry.go`
- Modify: `internal/loadbalancer/retry_test.go`

- [ ] **Step 1: Update health.go — add ctx and observe.Logger**

Add `ctx context.Context` as first parameter to these methods:

```go
func (h *AccountHealth) RecordSuccess(ctx context.Context, latencyUs int64)
func (h *AccountHealth) RecordError(ctx context.Context, statusCode int, retryAfter time.Duration, responseHeaders http.Header)
func (h *AccountHealth) RecordTimeout(ctx context.Context)
```

Replace all `slog.Warn(...)` / `slog.Error(...)` calls in these methods with `observe.Logger(ctx).Warn(...)` / `observe.Logger(ctx).Error(...)`. There are 7 slog calls total:
- health.go:101 `slog.Warn("account rate limited (true 429)", ...)` → `observe.Logger(ctx).Warn(...)`
- health.go:107 `slog.Warn("account rate limited (no reset headers)", ...)` → same
- health.go:115 `slog.Warn("account overloaded", ...)` → same
- health.go:124 `slog.Warn("account auth error, cooling down", ...)` → same
- health.go:135 `slog.Error("account disabled: too many consecutive 401s", ...)` → same
- health.go:142 `slog.Error("account forbidden, disabling", ...)` → same
- health.go:170 `slog.Warn("account cooldown: timeout threshold reached", ...)` → same

Add import for `"github.com/binn/ccproxy/internal/observe"`.

Also update `h.budget.RecordSuccess()` call inside `RecordSuccess` (health.go:72) to `h.budget.RecordSuccess(ctx)`.

- [ ] **Step 2: Add wasCoolingDown flag to health.go**

Add fields to `AccountHealth` struct using lock-free types to avoid upgrading `IsAvailable()`'s RLock:
```go
wasCoolingDown       atomic.Bool
lastCooldownDuration atomic.Int64 // stored as nanoseconds
```

Wherever a cooldown is set (in `RecordError` — each place that sets `h.cooldownUntil`), also set:
```go
h.wasCoolingDown.Store(true)
h.lastCooldownDuration.Store(int64(cooldownDuration))
```

In `IsAvailable()` (health.go:~185), after the existing check `time.Now().After(h.cooldownUntil)`, add recovery log using CAS to avoid duplicate logging:
```go
if h.wasCoolingDown.CompareAndSwap(true, false) {
	slog.Info("account recovered from cooldown",
		"account", h.Name,
		"cooldown_duration", time.Duration(h.lastCooldownDuration.Load()),
	)
}
```

This keeps `IsAvailable()` using RLock (no write to mutex-guarded state), avoiding performance impact on the hot `SelectAccount` path.

- [ ] **Step 3: Update budget.go — add ctx and observe.Logger**

Add `ctx context.Context` as first parameter to:

```go
func (bc *BudgetController) UpdateFromHeaders(ctx context.Context, headers http.Header)
func (bc *BudgetController) Record429(ctx context.Context, hasResetHeaders bool)
func (bc *BudgetController) RecordSuccess(ctx context.Context)
func (bc *BudgetController) checkStateChange(ctx context.Context)
```

Replace all slog calls with observe.Logger(ctx):
- budget.go:114 `slog.Debug("budget: headers updated", ...)` → `observe.Logger(ctx).Debug(...)`
- budget.go:174 `slog.Info("budget: state changed", ...)` → `observe.Logger(ctx).Info(...)`
- budget.go:204 `slog.Warn("budget: 429 recorded", ...)` → `observe.Logger(ctx).Warn(...)`
- budget.go:226 `slog.Info("budget: penalty recovered", ...)` → `observe.Logger(ctx).Info(...)`

Update internal calls: `checkStateChange()` calls within `UpdateFromHeaders` and `Record429` become `bc.checkStateChange(ctx)`.

Add import for `"github.com/binn/ccproxy/internal/observe"`.

- [ ] **Step 4: Update balancer.go — add ctx to ReportResult**

Change signature:
```go
func (b *Balancer) ReportResult(ctx context.Context, accountName string, statusCode int, latencyUs int64, retryAfter time.Duration, responseHeaders http.Header)
```

Update calls inside ReportResult:
- `h.RecordSuccess(latencyUs)` → `h.RecordSuccess(ctx, latencyUs)` (balancer.go:361)
- `h.budget.UpdateFromHeaders(responseHeaders)` → `h.budget.UpdateFromHeaders(ctx, responseHeaders)` (balancer.go:364)
- `h.RecordError(statusCode, retryAfter, responseHeaders)` → `h.RecordError(ctx, statusCode, retryAfter, responseHeaders)` (balancer.go:373)

Replace slog calls in `SelectAccount()` (already has ctx):
- balancer.go:107 `slog.Debug("backpressure: utilization delay", ...)` → `observe.Logger(ctx).Debug(...)`
- balancer.go:175 `slog.Debug("balancer: account filtered", ...)` → `observe.Logger(ctx).Debug(...)`
- balancer.go:246 `slog.Debug("balancer: account selected", ...)` → `observe.Logger(ctx).Debug(...)`

Keep `slog.Info("balancer: accounts updated", ...)` in `UpdateAccounts()` — non-request path.

- [ ] **Step 5: Add AccountStates method to Balancer (StateProvider)**

```go
func (b *Balancer) AccountStates() map[string]observe.AccountState {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states := make(map[string]observe.AccountState, len(b.accounts))
	for _, acct:= range b.accounts {
		name := acct.Name
		state := observe.AccountState{
			Concurrency:    b.tracker.ActiveSlots(name),
			MaxConcurrency: acct.MaxConcurrency,
		}
		if h, ok := b.health[name]; ok {
			if h.IsDisabled() {
				state.Health = "disabled"
			} else if !h.IsAvailable() {
				state.Health = "cooldown"
			} else {
				state.Health = "healthy"
			}
			state.BudgetState = h.Budget().State().String()
		}
		states[name] = state
	}
	return states
}
```

Add `"github.com/binn/ccproxy/internal/observe"` to imports if not already present.

- [ ] **Step 6: Update retry.go — replace slog and pass ctx to ReportResult**

Replace all `slog.XXX(...)` calls with `observe.Logger(ctx).XXX(...)`. All calls already have ctx available. Approximately 8-10 calls:
- retry.go:90 `slog.Warn("retry elapsed time exceeded", ...)` → `observe.Logger(ctx).Warn(...)`
- retry.go:101 `slog.Warn("no account available", ...)` → `observe.Logger(ctx).Warn(...)`
- retry.go:112 `slog.Debug("selected account", ...)` → `observe.Logger(ctx).Debug(...)`
- retry.go:173 `slog.Warn("failover: rate limited", ...)` → `observe.Logger(ctx).Warn(...)`
- retry.go:185 `slog.Warn("consecutive 529s across accounts, ...")` → `observe.Logger(ctx).Warn(...)`
- retry.go:201 `slog.Warn("failover immediate", ...)` → `observe.Logger(ctx).Warn(...)`
- retry.go:223 `slog.Warn("retry on same account", ...)` → `observe.Logger(ctx).Warn(...)`
- retry.go:266 `slog.Error("max account switches exceeded", ...)` → `observe.Logger(ctx).Error(...)`

Update all `balancer.ReportResult(accountName, ...)` calls to `balancer.ReportResult(ctx, accountName, ...)`. There are 4 calls:
- retry.go:137
- retry.go:182
- retry.go:207
- retry.go:243

- [ ] **Step 7: Add AccountsTried tracking to retry.go**

Add fields to `RetryResult`:
```go
type RetryResult struct {
	Response       *http.Response
	StatusCode     int
	AccountName   string
	Body           []byte
	AccountsTried []string
	Retries        int
	Failovers      int
}
```

In `ExecuteWithRetry()`, declare tracking variables:
```go
var accountsTried []string
retries := 0
failovers := 0
```

Append account name each time one is selected:
```go
accountsTried = append(accountsTried, accountName)
```

Increment `retries` on each same-account retry (where `sameAccountRetries++`), and `failovers` on each account switch (where `switchCount++`).

Include in return values:
```go
return &RetryResult{
	Response:       resp,
	StatusCode:     statusCode,
	AccountName:   accountName,
	AccountsTried: accountsTried,
	Retries:        retries,
	Failovers:      failovers,
}, nil
```

- [ ] **Step 8: Update all test files**

In `health_test.go`: add `context.Background()` as first argument to all `RecordSuccess`, `RecordError`, `RecordTimeout` calls.

In `budget_test.go`: add `context.Background()` as first argument to all `UpdateFromHeaders`, `Record429`, `RecordSuccess` calls.

In `balancer_test.go`: add `context.Background()` as first argument to all `ReportResult` calls.

In `retry_test.go`: update if any calls changed.

- [ ] **Step 9: Run all loadbalancer tests**

Run: `go test ./internal/loadbalancer/... -v -race`
Expected: ALL PASS

- [ ] **Step 10: Commit**

```bash
git add internal/loadbalancer/
git commit -m "feat(observe): context propagation across loadbalancer package

Add ctx parameter to AccountHealth.RecordSuccess/RecordError/RecordTimeout,
BudgetController.UpdateFromHeaders/Record429/RecordSuccess, and
Balancer.ReportResult. Replace all request-path slog calls with
observe.Logger(ctx). Add accounts_tried/retries/failovers tracking
to RetryResult. Add wasCoolingDown recovery logging. Implement
StateProvider interface on Balancer."
```

### Task 4: Update throttle.go and usage.go

**Files:**
- Modify: `internal/loadbalancer/throttle.go`
- Modify: `internal/loadbalancer/usage.go`

- [ ] **Step 1: Update throttle.go**

In `Enqueue()` (throttle.go:~102), replace `slog.Warn("throttle: queue timeout", ...)` with `observe.Logger(ctx).Warn(...)`. ctx is already a parameter.

`ShouldThrottle()` has no ctx — keep `slog.Debug(...)`.

- [ ] **Step 2: Update usage.go**

In `doFetch()`, replace all slog calls with `observe.Logger(ctx)`. There are 5 calls:
- usage.go:138 `slog.Debug("usage: token error", ...)`
- usage.go:155 `slog.Debug("usage: fetch error", ...)`
- usage.go:163 `slog.Warn("usage: API error", ...)`
- usage.go:170 `slog.Warn("usage: decode error", ...)`
- usage.go:176 `slog.Debug("usage: fetched", ...)`

Note: `doFetch` ctx comes from `FetchIfNeeded` which is called with `context.Background()` in balancer.go:370. These logs won't carry request_id — that's expected for background usage fetches.

- [ ] **Step 3: Run all loadbalancer tests**

Run: `go test ./internal/loadbalancer/... -v -race`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add internal/loadbalancer/throttle.go internal/loadbalancer/usage.go
git commit -m "feat(observe): context logger in throttle and usage"
```

---

## Chunk 3: Proxy, Disguise, OAuth Context Propagation

### Task 5: Update disguise/engine.go

**Files:**
- Modify: `internal/disguise/engine.go`

- [ ] **Step 1: Replace slog calls using origReq.Context()**

In `Apply()`, extract ctx at the top of the method:
```go
ctx := origReq.Context()
```

Replace all `slog.Debug(...)` calls with `observe.Logger(ctx).Debug(...)`. There are ~13 calls in Apply() (lines 53, 62, 85, 99, 115, 122, 130, 141, 153, 158, 175, 184, 197).

For `ApplyResponseModelID()` (line 254) — no request available, keep `slog.Debug(...)`.

Add import for `"github.com/binn/ccproxy/internal/observe"`.

- [ ] **Step 2: Run disguise tests**

Run: `go test ./internal/disguise/... -v -race`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/disguise/engine.go
git commit -m "feat(observe): context logger in disguise engine"
```

### Task 6: Update proxy/handler.go — doRequest() + request summary log

**Depends on:** Task 3 (RetryResult.Retries/Failovers/AccountsTried fields)

**Files:**
- Modify: `internal/proxy/handler.go`

- [ ] **Step 1: Replace slog calls in doRequest()**

In `doRequest()`, create logger from request context at the top:
```go
log := observe.Logger(origReq.Context())
```

Replace all `slog.XXX(...)` calls with `log.XXX(...)`:
- handler.go:312 `slog.Error("oauth manager not configured", ...)` → `log.Error(...)`
- handler.go:317 `slog.Error("oauth token error", ...)` → `log.Error(...)`
- handler.go:320 `slog.Debug("oauth token resolved", ...)` → `log.Debug(...)`
- handler.go:362 `slog.Debug("disguise applied", ...)` → `log.Debug(...)`
- handler.go:386 `slog.Debug("request cancelled", ...)` → `log.Debug(...)`
- handler.go:389 `slog.Error("upstream network error", ...)` → `log.Error(...)`
- handler.go:394 `slog.Warn("upstream returned error", ...)` → `log.Warn(...)`

Also replace the 2 slog calls in the `requestFn` closure (handler.go:167, 175):
- `slog.Info("signature error detected, ...")` → `log.Info(...)` (closure captures `log` from ServeHTTP scope)
- `slog.Info("signature+tool error detected, ...")` → `log.Info(...)`

- [ ] **Step 2: Update ReportResult call to pass ctx**

In handler.go:232, update:
```go
h.balancer.ReportResult(result.AccountName, result.StatusCode, ...)
```
to:
```go
h.balancer.ReportResult(r.Context(), result.AccountName, result.StatusCode, ...)
```

**Note:** This `ReportResult` call in handler.go:232 is duplicating the one already in retry.go:137 on the success path. This is pre-existing technical debt — leave it for now, flag for future cleanup.

- [ ] **Step 3: Add request summary log**

After `ExecuteWithRetry` returns (both success and failure paths), emit a summary log. Add this after the existing error/success handling, before the response is written:

```go
// Request summary log — level varies by outcome
summaryAttrs := []any{
	"model", originalModel,
	"stream", isStream,
	"elapsed", time.Since(requestStart).Round(time.Millisecond),
}

if result != nil {
	summaryAttrs = append(summaryAttrs,
		"account", result.AccountName,
		"status", result.StatusCode,
		"retries", result.Retries,
		"failovers", result.Failovers,
		"accounts_tried", result.AccountsTried,
	)
}

if err != nil {
	// Failure path
	log.Warn("request completed", summaryAttrs...)
} else if result.Retries > 0 || result.Failovers > 0 {
	// Success with retries
	log.Info("request completed", summaryAttrs...)
} else {
	// Clean success
	log.Debug("request completed", summaryAttrs...)
}
```

Place this right after the metrics recording (`observe.Global.RequestsError.Add(1)` or `observe.Global.RequestsSuccess.Add(1)`) and before the response writing. The existing "all retries exhausted" and "upstream success" log lines can remain or be removed — the summary replaces their purpose. Recommend keeping them for now to avoid changing too much at once.

- [ ] **Step 4: Add per-account metrics recording**

After request completion (both success and failure), record per-account metrics:
```go
if result != nil {
	im := observe.Global.Account(result.AccountName)
	im.RequestsTotal.Add(1)
	if result.StatusCode >= 200 && result.StatusCode < 300 {
		im.RequestsSuccess.Add(1)
	} else {
		im.RequestsError.Add(1)
	}
}
```

- [ ] **Step 5: Run proxy tests**

Run: `go test ./internal/proxy/... -v -race`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/handler.go
git commit -m "feat(observe): request summary log and context logger in proxy handler"
```

### Task 7: Update proxy/streaming.go and oauth/manager.go

**Files:**
- Modify: `internal/proxy/streaming.go`
- Modify: `internal/oauth/manager.go`

- [ ] **Step 1: Update streaming.go**

Replace the slog call in `ForwardSSE()` (streaming.go:114):
```go
slog.Warn("SSE error event received", ...)
```
→
```go
observe.Logger(ctx).Warn("SSE error event received", ...)
```

The `ctx` parameter is already available (streaming.go:62).

- [ ] **Step 2: Update oauth/manager.go**

Replace slog calls where ctx is available:
- manager.go:105 in `refreshToken()`: `slog.Info("token refreshed", ...)` → `observe.Logger(ctx).Info(...)`
- manager.go:142 in `ForceRefresh()`: `slog.Info("token force-refreshed", ...)` → `observe.Logger(ctx).Info(...)`

Keep `slog.XXX(...)` in `StartAutoRefresh()` goroutine — background context, not request.
Keep `slog.XXX(...)` in `MarkTokenExpired()` — no ctx.
Keep `slog.XXX(...)` in `ForceRefreshBackground()` — background goroutine.

- [ ] **Step 3: Add token expiry warning**

In `StartAutoRefresh()`, in the token check loop (manager.go:~186-197), after loading the token and checking `remaining`, add before the existing `< 60s` refresh logic:

```go
if remaining > 0 && remaining < 2*time.Minute {
	slog.Warn("oauth: token expiring soon",
		"account", accountName,
		"expires_in", remaining.Round(time.Second),
	)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/proxy/... ./internal/oauth/... -v -race`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/streaming.go internal/oauth/manager.go
git commit -m "feat(observe): context logger in streaming and oauth, token expiry warning"
```

---

## Chunk 4: Wiring and Final Verification

### Task 8: Wire StateProvider into server.go

**Files:**
- Modify: `internal/server/server.go`

- [ ] **Step 1: Update StartPeriodicLog call**

At server.go:113, change:
```go
observe.Global.StartPeriodicLog(ctx, 5*time.Minute)
```
to:
```go
observe.Global.StartPeriodicLog(ctx, 5*time.Minute, balancer, nil)
```

The `balancer` variable is in scope (created at server.go:~55). The last `nil` uses slog.Default().

- [ ] **Step 2: Run server tests**

Run: `go test ./internal/server/... -v -race`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/server/server.go
git commit -m "feat(observe): wire StateProvider into periodic metrics logging"
```

### Task 9: Full build and test

- [ ] **Step 1: Build the project**

Run: `make build`
Expected: Compiles successfully

- [ ] **Step 2: Run all tests**

Run: `make test`
Expected: ALL PASS with -race

- [ ] **Step 3: Fix any remaining compile or test errors**

Common issues:
- Missing ctx argument in test calls not yet updated
- Import cycle (should not happen — observe has no deps on loadbalancer)
- Mock objects needing updated method signatures

- [ ] **Step 4: Final commit if fixes were needed**

```bash
git add -A
git commit -m "fix: resolve remaining issues from observability enhancement"
```
