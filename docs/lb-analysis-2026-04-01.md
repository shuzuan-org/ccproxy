# ccproxy 负载均衡日志分析报告
**日期**: 2026-04-01 | **日志总行数**: 8487 | **分析时段**: 00:00–08:52 UTC | **服务器**: ccp1

---

## 1. 总览

| 指标 | 值 |
|------|-----|
| 今日新增请求（净增） | ~2083（累计 1865→3948） |
| 代理请求数（本段日志） | 2180 |
| 成功率 | 3946/3948 = **99.95%** |
| 累计错误 | 2（全天未增） |
| 账户数 | 2（`uuu`, `ceshi25`） |
| 请求速率 | avg 4.0 req/min，峰值 17.4 req/min |
| 节流事件 | **0** |
| OAuth 刷新 | 3 次，均成功 |

整体健康，成功率极高。

---

## 2. 会话亲和性 (L2 Sticky)

| 指标 | 值 |
|------|-----|
| 唯一 session_key | 2 |
| `default` 请求占比 | 2179/2180 = **99.95%** |
| sticky session hit | **0** |

**异常**: 2179 个请求使用固定 key `"default"`，完全没有触发任何 sticky hit 日志。session key 没有 UUID 后缀，说明客户端未传 `X-Claude-Code-Session-Id`（或传的是 `"default"` 这个字面量）。L2 层实际上没有工作，所有请求直接落到 L3 评分或直接绑定到固定账户。

---

## 3. 节流评估 (L1 Pool)

**结论**: 零节流事件，完全健康。当前流量（avg 4 req/min）远低于节流触发阈值，`minThrottleSamples` 守卫未被触发。

---

## 4. 预算追踪

**异常**: 全天 **0 条** `budget: headers updated` 日志、0 条 `usage: fetched` 日志、0 条任何 budget/usage 相关日志。预算子系统完全静默。

可能原因：
- 日志消息名称在近期版本变更，与 skill 中的名称不匹配
- `UpdateFromHeaders()` 未被调用（响应头中缺少利用率字段）
- 或预算追踪在此部署版本中被禁用

两账户 `metrics account` 全天显示 `budget: normal`，但这只是内存状态快照，无法确认追踪是否真实工作。**需排查**。

---

## 5. 多账户负载均衡 (L3 Score)

| 账户 | upstream success | metrics 累计 requests |
|------|------------------|-----------------------|
| `uuu` | **2180（100%）** | 1156→持续增长 |
| `ceshi25` | **0（0%）** | 707（日志开始时已有，今日零增） |

**严重问题**: `ceshi25` 今日完全无流量，尽管 `metrics account` 显示其 `state: healthy, budget: normal`。两个可能原因：

1. `selected account` 日志为 0 条——L3 评分选择日志根本没有发出，说明选择逻辑可能直接走了某条绕过路径（如 sticky 固定到 `uuu`）
2. L3 评分的权重/健康因子导致 `uuu` 永远胜出

注意 `ceshi25` 在此前日志中有 14 次 errors（requests=707, errors=14），错误率约 2%，这可能影响评分持续打低 `ceshi25`，但健康状态仍显示 healthy，值得核查评分计算逻辑。

---

## 6. 用户体验 & 延迟

### 6a. TTFB（首字节延迟）

| 模型 | n | p50 | p90 | 评估 |
|------|---|-----|-----|------|
| claude-opus-4-6 | 1182 | **3.65s** | **7.65s** | ✓ 正常（预期 2–4s / 5–8s） |
| claude-sonnet-4-6 | 810 | **2.61s** | **4.26s** | ⚠ 略高（预期 1–2s / 3–5s） |
| claude-haiku-4-5-20251001 | 188 | **0.78s** | **1.63s** | ✓ 正常（预期 <1s / 1–2s） |

Sonnet p50 偏高约 1s，可能与 thinking 块重试有关（见第 7 节）。

### 6b. 用户侧端到端延迟（`http request` /v1/messages 200）

| p50 | p90 | p95 | p99 | max |
|-----|-----|-----|-----|-----|
| 5.48s | 17.06s | 24.92s | 43.96s | **57.13s** |

p99/max 极高（44–57s）。最慢 5 个请求均在 52–57s，通常由大输出量驱动（SSE 流式时间 ≈ 总延迟 - TTFB ≈ 53s，说明是超长输出，非代理问题）。

### 6c. Token 用量（仅 1 条 request completed，样本极少）

```
input_tokens=3, output_tokens=161, cache_creation=116, cache_read=31911
```

单条记录显示 cache_read 极高（31911），缓存命中效果很好，但样本不足以统计。

### 6d. 非 Messages 端点

| 端点 | n | p50 | 评估 |
|------|---|-----|------|
| `/api/accounts` | 995 | 0.1ms | ✓ 正常 |
| `/admin/` | 2 | 0.5ms | ✓ 正常 |
| `/v1/messages/count_tokens` | 6 | 139.9ms | ✓ 正常 |

另检测到大量 WordPress 扫描探针（`/wp-includes/wlwmanifest.xml` 等 15+ 路径），全部快速响应（< 0.1ms），不影响服务。

---

## 7. 关键错误分析

### 7a. Thinking Block 签名错误（153 次）

```
"Invalid `signature` in `thinking` block" — stage: 0, account: uuu
```

**153/2180 = 7% 请求**触发了 thinking block 签名错误，代理检测到后过滤重试。重试成功（`requests_error` 仅为 2），但每次重试增加一轮完整的上游往返延迟，这是 Sonnet TTFB 偏高的可能原因。所有错误集中在 `uuu` 账户。

### 7b. metadata 注入错误（6 次）

```json
{"error": {"type": "invalid_request_error", "message": "metadata: Extra inputs are not permitted"}}
```

代理向 `metadata` 注入了 Anthropic API 不接受的额外字段，导致 6 次请求直接 400 失败。时间集中在 02:20–02:26 UTC。

### 7c. SSE 上游过载错误（22 次）

```json
{"type": "overloaded_error", "message": "Overloaded"}
```

Anthropic 上游在 SSE 流中返回过载错误。时间点分散（01:50、02:39、03:13、06:01 等），为上游偶发过载，非系统性问题。

### 7d. SSE 连接中断（18 次）

- `net/http: request canceled` — 客户端主动取消（用户中断请求）
- `connection reset by peer` — 网络重置

均为客户端行为导致，非代理问题。

---

## 8. 系统资源

| 指标 | 值 | 评估 |
|------|----|------|
| CPU% | avg 2.0%, max 4.5% | ✓ 健康 |
| load_1 | avg 0.03, max 0.27 | ✓ 极低 |
| Goroutines | 17→28, max 34 | ✓ 正常（随并发请求波动） |
| heap_alloc_mb | 2.1–22.3 MB, last 10.8 MB | ✓ 正常波动 |
| heap_sys_mb | 103 MB（稳定） | ✓ Go 运行时正常保留 |
| GC pause | avg 0.49ms, max 2.68ms | ✓ 优秀（< 3ms） |
| mem_total_mb | 961 MB | 读取的是宿主机内存（1GB VPS），非进程内存 |
| load_15 | avg ~0.03 | ✓ 无 I/O 瓶颈迹象 |

系统资源整体健康，无内存泄漏、无 Goroutine 泄漏迹象。

---

## 9. 优先建议

### P1 — 修复 metadata 注入

`"metadata: Extra inputs are not permitted"` 说明 disguise 引擎或 body 消毒逻辑向 `metadata` 注入了 Anthropic API 不识别的字段。检查 `internal/disguise/` 或 `internal/proxy/` 中的 metadata 处理代码，确认只注入 `user_id`（标准字段），移除任何扩展字段。

### P1 — 调查 ceshi25 零流量

`ceshi25` 今日完全无请求，但健康状态正常。需检查：
- L3 评分逻辑是否因历史 errors=14 将其评分打低至永远不被选中
- 或 session `"default"` 在某次早期绑定后固定到了 `uuu`，从未释放
- 添加 `selected account` 日志确认选择逻辑是否正常发出

### P2 — 排查预算追踪静默

全天 0 条 budget/usage 日志，需确认：
- `UpdateFromHeaders()` 是否在成功响应后被调用
- 日志消息名称是否与当前代码版本匹配
- `resets_at` 信息是否可用（多账户场景关键）

### P2 — Thinking block 重试率 7%

153 次重试（7%）对延迟有明显影响。考虑：
- 在转发前预先检查/剥离 thinking block signature（而非等上游拒绝后再重试）
- 或在客户端侧跟踪哪些会话有 thinking block，提前过滤

### P3 — session_key "default" 无 UUID

所有客户端发送的是字面量 `"default"` 作为 session key，L2 sticky 层完全没有发挥作用。如果客户端是 Claude Code CLI，检查 `X-Claude-Code-Session-Id` 是否被正确传递和解析。
