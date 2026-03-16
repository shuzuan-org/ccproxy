---
name: analyze-loadbalancer-logs
description: Analyze ccproxy runtime logs to evaluate load balancing, session affinity, throttle backpressure, and budget tracking. Use when user asks to analyze LB logs, check session affinity, review throttle behavior, evaluate budget tracking, diagnose balancer issues, or assess pool health. Triggers on keywords like "load balancing", "session affinity", "throttle", "budget", "backpressure", "balancer logs", "pool health".
---

# Analyze Load Balancer Logs

Evaluate ccproxy multi-account pool, session affinity, adaptive throttle, and budget tracking from Docker/runtime logs.

## Log Format

Same as analyze-disguise-logs: plain JSON or Docker JSON wrapper. For wrapper format, extract inner JSON:
```bash
cat logs/FILE.log | sed 's/.*"log":"//;s/\\n",.*//' | sed 's/\\"/"/g'
```

## Analysis Workflow

### 1. Overview Metrics

Extract `metrics summary` logs (emitted every 5 min):

| Field | Meaning |
|-------|---------|
| `requests_total` | Cumulative proxy requests |
| `requests_per_min` | Rate in last 5-min window |
| `requests_success` / `requests_error` | Success vs failure |
| `requests_throttled` | Cold-window throttle activations |
| `requests_queued` | Requests that entered wait queue |
| `retries_total` / `failovers_total` | Retry and failover counts |
| `accounts_429` / `accounts_529` | Accounts hitting rate limit or overload |

Extract `metrics account` logs per account:

| Field | Meaning |
|-------|---------|
| `state` | `healthy` / `degraded` / `blocked` |
| `concurrency` | `active/max` slots |
| `budget` | `normal` / `sticky_only` / `blocked` |
| `errors_429` / `errors_529` | Per-account upstream errors |

**Derived metrics**: success rate = `success / total`, error rate by account, peak concurrency.

### 2. Session Affinity (L2 Sticky)

#### 2a. Sticky Hit Rate

Log: `balancer: sticky session hit` — count vs total `proxy request` count.

**Formula**: `sticky_hits / total_proxy_requests`. Misses are first-request-per-session (expected).

**Healthy**: hit rate = `1 - (unique_sessions / total_requests)`. If lower, sessions are being evicted prematurely (check TTL config).

#### 2b. Session Distribution

Extract `session_key` from `proxy request` logs. Count requests per session to identify:
- Dominant sessions (> 50% traffic) — normal for single-user setups
- Very short sessions (1-2 requests) — may indicate client reconnection issues
- Session count vs API key count — should correlate

#### 2c. Account Binding

Log: `session: bound` — verify sessions consistently bind to the same account.

Log: `selected account` with `switch` field — non-zero `switch` means the balancer changed account mid-selection (account was full/unhealthy). Frequent switches indicate capacity pressure.

### 3. Adaptive Throttle (L1 Pool)

#### 3a. Cold Window Problem

Log: `throttle: request throttled` with fields `probability`, `requests`, `accepts`.

**Signature of cold-window misfire**: `requests=1, accepts=0, probability=0.5`. This means the 2-min sliding window was empty after idle, and the first request was unnecessarily throttled.

**Check**: `minThrottleSamples` guard (currently 3) should prevent `requests < 3` from triggering. If logs still show `requests=1` throttles, the guard is not deployed or not effective.

**Measure impact**: count throttle events, correlate with idle gaps (> 2 min between requests).

#### 3b. Genuine Throttle

Genuine throttle: `requests >> 2 * accepts` in window. This means upstream is rejecting requests and backpressure is appropriate.

**Never seen in low-traffic scenarios** — if it appears, investigate upstream 429/529 errors.

#### 3c. Queue Behavior

`requests_throttled` should equal `requests_queued` — every throttled request enters the queue. If `queued < throttled`, requests are being dropped (queue full or timeout).

Scan for `throttle: queue timeout` — indicates queue capacity exceeded.

### 4. Budget Tracking (Dual Window)

#### 4a. Usage API Freshness

Log: `usage: fetched` with `5h_util` and `7d_util` (integer percentages from Anthropic API).

Log: `budget: usage API updated` — fires when fetcher writes new data.

**Fetch interval analysis**: The background ticker fires every 3 min, but `FetchIfNeeded()` checks `budget.HasRecentData(5min)` before calling the API. Since `UpdateFromHeaders()` is called on every proxy response and refreshes `LastUpdated`, active traffic suppresses API fetches entirely.

**Expected interval patterns**:
- **~6m** — idle period, no requests updating headers, 2 ticker cycles needed for `HasRecentData` to expire
- **~18m** — low-frequency requests keep headers alive across multiple ticker cycles
- **100m+** — sustained traffic, headers continuously refresh `LastUpdated`, API never fires until a request gap > 5 min appears

These patterns are **by design**, not errors. Only flag as problematic if:
- `usage: token error` or `usage: fetch error` or `usage: API error` logs appear during gaps
- Budget state transitions (`normal` → `sticky_only` → `blocked`) are delayed because stale API data missed a utilization spike

#### 4d. Header vs API Data Precision

Response headers and API return nearly identical utilization values:
- **Max delta**: ±0.01 (1 percentage point), caused by rounding — API returns integers (e.g., `9`), headers return floats (e.g., `0.08`)
- **7d column** consistently shows header ~0.01 below API (e.g., API `9%` → header `0.08`)
- **5h column** typically matches exactly or within 0.01

During sustained traffic, headers track utilization changes faithfully (confirmed: header tracked 5h from 0.02→0.11 over 111 min, API confirmed 0.12 at next fetch — only 0.01 delta).

**Implication**: In single-account low-load scenarios, header-only budget tracking is sufficient. The risk emerges in multi-account high-load scenarios where `resets_at` timestamps (only available from API) become critical for budget state transitions.

#### 4b. Budget State

Log: `budget: headers updated` with `util_5h`, `util_7d` (decimal 0-1 for header injection), `state`.

States:
- `normal` — both windows below thresholds, all routing modes available
- `sticky_only` — approaching limit, only sticky sessions allowed (no new bindings)
- `blocked` — over limit, account excluded from selection

**Mapping check**: API integer `9` should map to header `0.09`, not `0.08` — verify precision.

#### 4c. Utilization Delay

`UtilizationDelay` activates when pool utilization > 0.5. In low-traffic single-account scenarios this is never triggered. Under load, look for increased request latency when `util_5h` or `util_7d` exceeds 50%.

### 5. Multi-Account Load Balancing (L3 Score)

**Only testable with 2+ accounts.** With single account, every request selects the only option.

When multi-account is active, check:
- `selected account` distribution — should be balanced unless budget/health differs
- `accounts_tried` in `request completed` — multiple entries means failover occurred
- `retries` and `failovers` fields — non-zero means upstream errors triggered retry logic
- `switch` in `selected account` — non-zero means initial selection was overridden

### 6. Latency Profile

From `request completed` logs, extract `elapsed` (nanoseconds), `model`, `status`:

| Metric | How |
|--------|-----|
| Percentiles | Sort elapsed, compute p50/p90/p99 |
| By model | Group by model — opus > sonnet > haiku is expected |
| Long tail | max > 10s warrants investigation (upstream cold start?) |
| Failed requests | Non-200 status with high elapsed = upstream timeout |

## Report Template

1. **Overview** — uptime, total requests, success rate, account count, error rate
2. **Session Affinity** — hit rate, session distribution, binding consistency
3. **Throttle Assessment** — cold-window misfires count, genuine throttle events, queue health
4. **Budget State** — usage trajectory, state transitions, precision check
5. **Multi-Account Balance** — distribution, failover events (or note "single account — untested")
6. **Latency** — percentiles by model, outliers
7. **Recommendations** — prioritized (P0/P1/P2/P3) with specific action items

## Key Principles

- Single-account logs CANNOT validate multi-account LB, failover, or score-based selection — always note this limitation
- Cold-window throttle (`requests=1, accepts=0`) is a known issue, not genuine backpressure — do NOT conflate with real throttle events
- `requests_throttled == requests_queued` is healthy; divergence means queue drops
- Budget `normal` under low load is expected, not evidence of correctness under pressure
- `switch:0` on all requests with single account is trivially correct — not meaningful validation
- Concurrency `0/N` or `1/N` in snapshots is normal for low-traffic; only peak matters
- Usage API integer-to-decimal mapping has consistent ±0.01 rounding delta (e.g., API `9` → header `0.08`), this is normal — only flag if delta > 0.02
- Long usage API fetch gaps (e.g., 100m+) during active traffic are expected — `HasRecentData()` is satisfied by response headers. Only diagnose as a problem if error logs (`usage: token error`, `usage: fetch error`, `usage: API error`) appear during the gap
- To diagnose fetch gaps: check for `budget: headers updated` during the gap period — if present, the gap is caused by header suppression (benign); if absent, investigate token/network errors
