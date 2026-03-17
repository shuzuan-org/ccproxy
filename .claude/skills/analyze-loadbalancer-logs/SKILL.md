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

### 6. User Experience & Latency

A request goes through three measurable phases: **TTFB (first byte wait)** → **SSE streaming** → **completion**. Analyze each layer separately to identify where latency originates.

#### 6a. Latency Layering

Three log sources provide different latency views:

| Log | Field | Measures |
|-----|-------|----------|
| `upstream success` | `elapsed` (ns) | TTFB — time from proxy sending request to receiving first upstream byte (model thinking time + network) |
| `request completed` | `elapsed` (ns) | End-to-end — TTFB + full SSE stream read + token extraction |
| `http request` | `elapsed` (Go duration string) | User-facing — includes TLS, auth, routing, proxy, SSE streaming |

**SSE streaming duration** = `request completed` elapsed - `upstream success` elapsed (for same `request_id`).

**Proxy overhead** = `http request` elapsed - `request completed` elapsed. Typically < 500ms (middleware stack: auth, rate limit, disguise, routing). If consistently > 1s, investigate middleware bottleneck.

Compute p50/p90/p95/p99/max for each layer. Note: `http request` elapsed uses Go duration strings (e.g., `7.132916625s`, `129.359µs`) — parse appropriately. Filter `/v1/messages` with status 200 for meaningful latency analysis.

#### 6b. TTFB (First Byte Latency)

This is the most important user-perceived metric — how long until the user starts seeing output.

**Expected by model**:
- Opus: p50 = 2-4s, p90 = 5-8s (includes thinking time)
- Sonnet: p50 = 1-2s, p90 = 3-5s
- Haiku: p50 < 1s, p90 = 1-2s

If TTFB is significantly higher than expected, check:
- TLS handshake time (from `tls: handshake success` logs)
- Throttle queue wait time
- Budget delay (UtilizationDelay when utilization > 50%)

#### 6c. SSE Streaming Duration & Output Throughput

Compute output throughput: `output_tokens / (request_completed_elapsed / 1e9)` = tokens/sec.

**Filter**: Only include requests with `output_tokens > 10` and elapsed > 0.5s to avoid skewing from tool-use or empty responses.

**Expected**: Opus p50 ~25-35 tok/s, Sonnet ~50-80 tok/s. Low throughput (< 5 tok/s) on individual requests may indicate extended thinking blocks (not a proxy issue).

Long tail latency (p99, max) is almost always driven by large output volume, not proxy issues. Correlate: requests with max elapsed should also have max `output_tokens`. If high latency occurs with low output tokens, investigate upstream or proxy issues.

#### 6d. Token Usage & Prompt Caching

From `request completed` logs, extract per-request token fields:

| Field | Meaning |
|-------|---------|
| `input_tokens` | Non-cached input tokens processed |
| `output_tokens` | Generated output tokens |
| `cache_creation` | Tokens written to prompt cache |
| `cache_read` | Tokens read from prompt cache (cache hit) |

**Derived metrics**:
- **Cache hit rate**: requests with `cache_read > 0` / total requests
- **Cache read ratio**: `cache_read / (input_tokens + cache_creation + cache_read)` — proportion of total input served from cache
- **Output distribution**: p50/p90/p99/max of `output_tokens` — explains latency tail

**Healthy caching**: cache hit rate > 90%, cache read ratio > 80%. High cache_read with low input_tokens means system prompts and conversation history are being cached effectively, reducing both latency and cost.

**Token-latency correlation**: Large `output_tokens` (> 1500) directly causes high end-to-end latency. Always present the top 3-5 largest requests with their output tokens alongside elapsed time to demonstrate this correlation.

#### 6e. Admin & Non-Messages Endpoints

Extract latency for non-`/v1/messages` paths from `http request` logs:

| Endpoint | Expected |
|----------|----------|
| `/api/accounts` | < 1ms (in-memory lookup) |
| `/admin/` | < 10ms (static HTML serving) |
| `/v1/messages/count_tokens` | 200-500ms (upstream API call) |

Flag if admin endpoints exceed 50ms — may indicate resource contention.

#### 6f. Latency Percentiles (Legacy)

From `request completed` logs, extract `elapsed` (nanoseconds), `model`, `status`:

| Metric | How |
|--------|-----|
| Percentiles | Sort elapsed, compute p50/p90/p95/p99 |
| By model | Group by model — opus > sonnet > haiku is expected |
| Long tail | Almost always caused by large output_tokens, not proxy issues — verify correlation |
| Failed requests | Non-200 status with high elapsed = upstream timeout |

### 7. System Resources

Extract `metrics system` logs (emitted every 5 min alongside other metrics):

| Field | Meaning |
|-------|---------|
| `cpu_percent` | Process CPU usage (%) |
| `goroutines` | Active goroutine count |
| `heap_alloc_mb` | Go heap currently allocated |
| `heap_sys_mb` | Go heap reserved from OS |
| `gc_cycles` | Cumulative GC cycle count |
| `gc_pause_ms` | Last GC pause duration |
| `mem_total_mb` | System/container total memory |
| `mem_used_mb` | System/container used memory |
| `mem_percent` | Memory usage percentage |
| `load_1` / `load_5` / `load_15` | System load averages |

#### 7a. CPU Analysis

Extract min/max `cpu_percent` across all snapshots. Correlate peaks with `requests_per_min` from metrics summary.

**Healthy**: < 10% for low-traffic. Spikes correlate with request bursts.

Note: `GOMAXPROCS=1: CPU quota undefined` in startup logs indicates container environment. CPU metrics are container-scoped.

#### 7b. Go Runtime Health

| Metric | Healthy | Warning |
|--------|---------|---------|
| Goroutines | Stable baseline (10-15 idle), rises with active requests, returns to baseline | Monotonically increasing = goroutine leak |
| Heap alloc | Low (1-5 MB typical), fluctuates with request load | Monotonically increasing = memory leak |
| Heap sys | Stable after warmup (~80 MB is normal Go runtime reservation) | Continuous growth = fragmentation |
| GC pause | < 5 ms | > 10 ms may cause SSE stream stuttering |
| GC cycles | Proportional to allocation rate | Excessive rate with low alloc = GC thrashing |

**Goroutine leak detection**: Compare goroutine count at start vs end of log. Idle count should be similar. Each active request adds ~2-3 goroutines (handler + SSE reader). If idle count drifts upward, investigate unclosed connections.

**Heap analysis**: `heap_alloc` is live objects; `heap_sys` is OS reservation. A large gap (e.g., alloc=2MB, sys=80MB) is normal — Go retains memory for future allocations. Only flag if `heap_sys` grows continuously.

#### 7c. Memory: Understanding the Metrics

**CRITICAL**: `mem_total_mb` / `mem_used_mb` / `mem_percent` from gopsutil reflect the **host or container-level** view depending on cgroup configuration:

- In cgroup-limited containers: reads cgroup memory limit and usage
- In containers WITHOUT cgroup memory limit: reads **host** `/proc/meminfo` — values represent the entire machine, not the container

**How to tell which**: If `mem_total_mb` matches the VPS total RAM (e.g., 961 MB on a 1 GB VPS), it's reading the host. If it matches a specific Docker `--memory` limit, it's cgroup-scoped.

**gopsutil `mem.Used` inflates real usage** — it includes:
- Process RSS (actual process memory)
- Page cache (file system cache, reclaimable by kernel)
- Slab cache (partially reclaimable)

To understand true memory usage, cross-reference with:
1. `docker stats --no-stream` — cgroup actual memory, **most accurate for container usage** (excludes shared page cache)
2. `ps aux --sort=-%mem` — per-process RSS (includes shared library double-counting across processes)
3. `/proc/meminfo` — full breakdown: `AnonPages` (true process memory), `Cached+Buffers` (reclaimable), `MemAvailable` (actual headroom)

**Key relationships**:
- `docker stats` MEM < sum of `ps` RSS — because RSS double-counts shared libraries (libc, libssl, etc.)
- `gopsutil mem_used` >> `docker stats` MEM — because gopsutil includes page cache and kernel memory
- `MemAvailable` is the authoritative "how much memory is actually free" metric

**Memory trend analysis**: A downward trend in `mem_used_mb` over time typically reflects page cache eviction, not memory being freed by processes. An upward trend may be cache warming, not a leak. Always check `heap_alloc_mb` for Go-specific memory trends.

#### 7d. System Load

`load_1/5/15` on a 1 vCPU machine: values > 1.0 mean CPU saturation. For ccproxy's typical workload (I/O-bound proxy), load should stay well under 0.5.

Peak `load_1` > 0.5 with low `cpu_percent` suggests I/O wait (check `%iowait` via `mpstat`).

## Report Template

1. **Overview** — uptime, total requests, success rate, account count, error rate
2. **Session Affinity** — hit rate, session distribution, binding consistency
3. **Throttle Assessment** — cold-window misfires count, genuine throttle events, queue health
4. **Budget State** — usage trajectory, state transitions, precision check
5. **Multi-Account Balance** — distribution, failover events (or note "single account — untested")
6. **User Experience** — TTFB, streaming throughput, token usage, caching, latency layering
7. **System Resources** — CPU, memory, Go runtime health
8. **Recommendations** — prioritized (P0/P1/P2/P3) with specific action items

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
- **Memory**: gopsutil `mem_used` is NOT process memory — it includes page cache and kernel caches. Use `docker stats` for true container memory, `AnonPages` from `/proc/meminfo` for true process memory across the host. Never report gopsutil mem_used as "process memory usage"
- **RSS vs docker stats**: `ps` RSS double-counts shared libraries across processes. `docker stats` MEM is the accurate container-level figure. Example: Caddy 48MB + ccproxy 17MB RSS = 65MB, but docker stats shows 22MB — the delta is shared library pages counted by both processes
- **Go heap_sys vs heap_alloc**: `heap_sys` (~80MB) is Go runtime's OS reservation, not actual usage. `heap_alloc` (1-5MB typical) is live objects. Do NOT report heap_sys as memory consumption
- **Goroutine baseline**: 12-13 idle goroutines is normal for ccproxy (timers, health checks, budget fetcher, etc.). Only flag growth if idle count drifts upward over hours
- **GC pause**: < 2ms is excellent for SSE streaming proxy. Only flag if consistently > 5ms
- **Container vs host memory**: When `mem_total_mb` equals VPS total RAM, gopsutil is reading host meminfo, not cgroup — note this in the report to avoid confusion
- **Latency layering**: Always decompose into TTFB + streaming + proxy overhead. Report each layer separately — do NOT just report a single "average latency" number. The user cares about "when do I start seeing output" (TTFB) and "how fast does output stream" (tok/s) separately
- **TTFB is the key UX metric**: p50 TTFB for Opus ~3s, Sonnet ~1.5s, Haiku ~0.5s. Higher than expected → check TLS handshake, throttle queue, budget delay. Normal TTFB with high total latency → large output volume, not a proxy issue
- **Tail latency attribution**: p99/max latency is almost always driven by large `output_tokens` (> 1500). Always correlate the slowest requests with their output token count before attributing latency to proxy issues
- **Output throughput**: Opus ~25-35 tok/s, Sonnet ~50-80 tok/s at p50. Filter `output_tokens > 10 && elapsed > 0.5s` to avoid skewing. Extremely low tok/s (< 5) on individual requests typically means extended thinking, not degradation
- **Proxy overhead**: Difference between `http request` elapsed and `request completed` elapsed. Should be < 500ms. This includes auth, rate limit, disguise, routing middleware. If > 1s, investigate middleware stack
- **Prompt caching**: Cache hit rate > 90% and cache read ratio > 80% is healthy. High `cache_read` with low `input_tokens` means the system is working as intended — system prompts and conversation context are cached
- **Token-latency correlation**: Present top 3-5 largest output requests alongside their elapsed time to demonstrate that tail latency = large output, not proxy degradation
- **Admin endpoint latency**: `/api/accounts` should be < 1ms, `/admin/` < 10ms. These are in-memory operations — flag if > 50ms
