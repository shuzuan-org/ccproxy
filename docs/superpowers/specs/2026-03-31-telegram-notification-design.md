# ccproxy Telegram 通知设计

**日期**：2026-03-31
**状态**：待实现

## 概述

当账户出现异常（被禁用、限速、过载、预算阻断等）时，通过 Telegram Bot 向管理员发送通知。配置通过管理仪表盘动态管理，无需重启服务。

---

## 事件模型

### 两大类别

**类别一：账户被禁用（永久，需人工介入）**
- `account_disabled`：连续 3 次 401 触发禁用
- `account_banned`：平台封禁（403 / OAuth not allowed / organization disabled）

**类别二：其他异常（可自动恢复）**
- `rate_limited`：真 429（含 anthropic-ratelimit reset headers）
- `overloaded`：529 过载冷却
- `timeout_cooldown`：连续超时达到阈值触发冷却
- `budget_blocked`：Budget 状态进入 StateBlocked

---

## 包结构

新建 `internal/notify/` 包：

```
internal/notify/
  notifier.go       # Notifier 接口、Event 结构、EventType 常量、NoopNotifier、全局单例
  telegram.go       # TelegramNotifier 实现（调用 Telegram Bot API sendMessage）
  dedup.go          # 去重器：同账户同事件类型 5 分钟内最多发一次
  config.go         # NotifyConfig 结构、load/save 到 data/notify.json
  notifier_test.go
  telegram_test.go
  dedup_test.go
  config_test.go
```

### 核心接口

```go
type Notifier interface {
    Notify(ctx context.Context, event Event) error
}

type Event struct {
    AccountName string
    Type        EventType
    Detail      string    // e.g. "cooldown: 60s", "reason: platform_forbidden"
}

type EventType string

const (
    // 类别一：禁用
    EventAccountDisabled EventType = "account_disabled"
    EventAccountBanned   EventType = "account_banned"
    // 类别二：其他异常
    EventRateLimited     EventType = "rate_limited"
    EventOverloaded      EventType = "overloaded"
    EventTimeoutCooldown EventType = "timeout_cooldown"
    EventBudgetBlocked   EventType = "budget_blocked"
)

func (e EventType) Category() EventCategory

type EventCategory int
const (
    CategoryDisabled EventCategory = iota
    CategoryAnomaly
)
```

### 全局单例

```go
// global holds the active Notifier. Protected by globalMu for concurrent access.
var (
    globalMu sync.RWMutex
    global   Notifier = &NoopNotifier{}
)

// SetGlobal atomically replaces the active Notifier.
func SetGlobal(n Notifier) { globalMu.Lock(); global = n; globalMu.Unlock() }

// Global returns the active Notifier.
func Global() Notifier { globalMu.RLock(); defer globalMu.RUnlock(); return global }
```

`NoopNotifier.Notify()` 直接返回 nil，零开销。调用方使用 `notify.Global().Notify(...)`。

---

## 配置

### 结构

```go
type NotifyConfig struct {
    BotToken       string `json:"bot_token"`
    ChatID         string `json:"chat_id"`
    EnableDisabled bool   `json:"enable_disabled"` // 类别一开关
    EnableAnomaly  bool   `json:"enable_anomaly"`  // 类别二开关
}
```

存储路径：`data/notify.json`，权限 0600，原子写入（复用 `fileutil`）。

---

## 去重器

```go
type Dedup struct {
    mu      sync.Mutex
    entries map[string]time.Time // key: "accountName:eventType"
    ttl     time.Duration        // 5 分钟
}

func (d *Dedup) Allow(account string, event EventType) bool
// 返回 true 并更新时间戳；同 key 5 分钟内再次调用返回 false
```

`TelegramNotifier` 内置 `Dedup`，`Notify()` 先过去重器再发送。

---

## TelegramNotifier

- 内置独立 `http.Client`（timeout 10s），不使用全局代理/伪装引擎
- 调用 `https://api.telegram.org/bot{token}/sendMessage`
- 发送失败仅记录 `slog.Warn`，不阻塞业务请求
- 消息格式：

```
⚠️ [ccproxy] 账户异常通知

账户：my-account
事件：真速率限制 (429)
详情：冷却 87s，重置时间 15:30 UTC
时间：2026-03-31 15:28:43 UTC
```

禁用类事件使用 `🔴`，其他异常使用 `⚠️`。

---

## 调用点

共 5 处，全在 `internal/loadbalancer/`，直接调用全局单例：

| 文件 | 位置 | 事件 |
|------|------|------|
| `health.go` | `Disable()` | `EventAccountDisabled` 或 `EventAccountBanned`（根据 reason 区分） |
| `health.go` | `RecordError()` 真 429 分支 | `EventRateLimited` |
| `health.go` | `RecordError()` 529 分支 | `EventOverloaded` |
| `health.go` | `RecordTimeout()` 阈值触发时 | `EventTimeoutCooldown` |
| `budget.go` | `checkStateChange()` 进入 `StateBlocked` 时 | `EventBudgetBlocked` |

调用方式：

```go
notify.Global().Notify(ctx, notify.Event{
    AccountName: h.Name,
    Type:        notify.EventRateLimited,
    Detail:      fmt.Sprintf("cooldown: %s", cd),
})
```

---

## 初始化流程

启动时（`cmd/ccproxy/main.go`）：

1. 尝试从 `data/notify.json` 加载 `NotifyConfig`
2. 若文件不存在或 `bot_token` / `chat_id` 为空 → `notify.Global()` 保持 `NoopNotifier`
3. 否则 → 初始化 `TelegramNotifier`，调用 `notify.SetGlobal()`

管理员通过仪表盘保存配置时（`POST /api/notify/config`）：

1. 写入 `data/notify.json`
2. 调用 `notify.SetGlobal(newNotifier)`，立即生效，无需重启

---

## Admin API

| 方法 | 路径 | 说明 |
|------|------|------|
| `GET` | `/api/notify/config` | 返回当前配置，`bot_token` 脱敏（`****<后4位>`） |
| `POST` | `/api/notify/config` | 保存配置，原子替换全局 Notifier |
| `POST` | `/api/notify/test` | 发送测试消息，返回成功/失败 |

新增处理器文件：`internal/admin/notify_handlers.go`

---

## 仪表盘 UI

在账户列表卡片**下方**新增"Telegram 通知"卡片（内嵌于 `index.html`，无外部依赖）：

```
┌─────────────────────────────────────────────┐
│  Telegram 通知配置                            │
│                                             │
│  Bot Token  [**************abcd]            │
│  Chat ID    [-1001234567890      ]          │
│                                             │
│  通知类别                                    │
│  ☑ 账户被禁用（连续401、平台封禁）               │
│  ☑ 其他异常（429 / 529 / 超时 / 预算阻断）       │
│                                             │
│  [保存配置]              [发送测试消息]         │
│                                             │
│  状态提示区（inline 显示成功/失败）              │
└─────────────────────────────────────────────┘
```

---

## 测试策略

- `dedup_test.go`：TTL 边界、并发安全
- `telegram_test.go`：用 `httptest.Server` mock Telegram API，验证请求格式、类别过滤、去重
- `config_test.go`：load/save 往返、权限、原子写入
- `notify_handlers_test.go`：GET 脱敏、POST 保存、POST test 成功/失败路径
- 所有单元测试使用 `t.Parallel()`，带 `-race`
