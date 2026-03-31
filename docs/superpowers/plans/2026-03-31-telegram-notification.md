# Telegram 账户异常通知 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 当账户出现禁用/封禁/限速/过载/超时/预算阻断等异常时，通过 Telegram Bot 向管理员发送通知；配置通过管理仪表盘动态管理，无需重启。

**Architecture:** 新建 `internal/notify/` 包，包含 Notifier 接口、TelegramNotifier 实现、5 分钟去重器和 JSON 配置持久化；全局单例通过读写锁保护，admin 保存配置时原子替换；5 个调用点散布于 `health.go` 和 `budget.go` 中，通过 goroutine 或直接调用触发通知。

**Tech Stack:** Go 标准库（`net/http`、`sync`、`encoding/json`）、`fileutil.AtomicWriteFile`（已有）、Telegram Bot API `sendMessage`。

---

## 文件映射

**新建文件：**
- `internal/notify/notifier.go` — 接口、事件类型、NoopNotifier、全局单例
- `internal/notify/dedup.go` — 5 分钟 TTL 去重器
- `internal/notify/config.go` — NotifyConfig 结构、load/save data/notify.json
- `internal/notify/telegram.go` — TelegramNotifier（HTTP client + dedup + 消息格式化）
- `internal/notify/notifier_test.go`
- `internal/notify/dedup_test.go`
- `internal/notify/config_test.go`
- `internal/notify/telegram_test.go`
- `internal/admin/notify_handlers.go` — HandleNotifyConfig（GET/POST）、HandleNotifyTest
- `internal/admin/notify_handlers_test.go`

**修改文件：**
- `internal/loadbalancer/health.go` — Disable()、RecordError() 429/529、RecordTimeout() 加 notify 调用
- `internal/loadbalancer/budget.go` — checkStateChange() 进入 StateBlocked 时加 notify 调用
- `internal/loadbalancer/health_notify_test.go` — 新建（notify 集成测试）
- `internal/loadbalancer/budget_notify_test.go` — 新建（notify 集成测试）
- `internal/admin/handler.go` — Handler 加 dataDir 字段，NewHandler 加参数
- `internal/admin/handler_test.go` — newTestHandler 传入 dataDir
- `internal/server/server.go` — 启动时初始化 notify，注册 /api/notify/* 路由，传 dataDir 给 admin.NewHandler
- `internal/admin/static/index.html` — 新增 Telegram 配置卡片 + JS

---

### Task 1: notify 包核心类型

**Files:**
- Create: `internal/notify/notifier.go`
- Create: `internal/notify/notifier_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/notify/notifier_test.go`：

```go
package notify

import (
	"context"
	"testing"
)

func TestNoopNotifier(t *testing.T) {
	t.Parallel()
	n := &NoopNotifier{}
	if err := n.Notify(context.Background(), Event{AccountName: "test", Type: EventAccountDisabled}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestGlobalSingleton(t *testing.T) {
	// Do NOT use t.Parallel() — modifies global state.
	orig := Global()
	defer SetGlobal(orig)

	mock := &mockNotifier{}
	SetGlobal(mock)
	if Global() != mock {
		t.Fatal("SetGlobal did not update Global()")
	}
}

func TestEventTypeCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		e    EventType
		want EventCategory
	}{
		{EventAccountDisabled, CategoryDisabled},
		{EventAccountBanned, CategoryDisabled},
		{EventRateLimited, CategoryAnomaly},
		{EventOverloaded, CategoryAnomaly},
		{EventTimeoutCooldown, CategoryAnomaly},
		{EventBudgetBlocked, CategoryAnomaly},
	}
	for _, tc := range cases {
		if got := tc.e.Category(); got != tc.want {
			t.Errorf("%s: want %v, got %v", tc.e, tc.want, got)
		}
	}
}

// mockNotifier is shared across test files in this package.
type mockNotifier struct {
	events []Event
}

func (m *mockNotifier) Notify(_ context.Context, e Event) error {
	m.events = append(m.events, e)
	return nil
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/notify/... -v -race
```

期望：编译错误（包不存在）。

- [ ] **Step 3: 实现 notifier.go**

新建文件 `internal/notify/notifier.go`：

```go
package notify

import (
	"context"
	"sync"
)

// EventType identifies a specific account anomaly event.
type EventType string

const (
	// CategoryDisabled events — permanent, require manual intervention.
	EventAccountDisabled EventType = "account_disabled" // consecutive 401s
	EventAccountBanned   EventType = "account_banned"   // platform ban (403/400)

	// CategoryAnomaly events — recoverable.
	EventRateLimited     EventType = "rate_limited"     // true 429 with reset headers
	EventOverloaded      EventType = "overloaded"       // 529
	EventTimeoutCooldown EventType = "timeout_cooldown" // timeout threshold reached
	EventBudgetBlocked   EventType = "budget_blocked"   // budget state → Blocked
)

// EventCategory classifies an event for subscription filtering.
type EventCategory int

const (
	CategoryDisabled EventCategory = iota // account permanently disabled
	CategoryAnomaly                       // recoverable anomaly
)

// Category returns the category of this event type.
func (e EventType) Category() EventCategory {
	switch e {
	case EventAccountDisabled, EventAccountBanned:
		return CategoryDisabled
	default:
		return CategoryAnomaly
	}
}

// Event represents an account anomaly to be notified.
type Event struct {
	AccountName string
	Type        EventType
	Detail      string // human-readable context, e.g. "cooldown: 60s"
}

// Notifier sends account anomaly notifications.
type Notifier interface {
	Notify(ctx context.Context, event Event) error
}

// NoopNotifier discards all notifications. Used as default before config is loaded.
type NoopNotifier struct{}

func (n *NoopNotifier) Notify(_ context.Context, _ Event) error { return nil }

var (
	globalMu sync.RWMutex
	global   Notifier = &NoopNotifier{}
)

// SetGlobal replaces the active Notifier. Safe for concurrent use.
func SetGlobal(n Notifier) {
	globalMu.Lock()
	global = n
	globalMu.Unlock()
}

// Global returns the active Notifier. Safe for concurrent use.
func Global() Notifier {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}
```

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/notify/... -v -race
```

期望：PASS，3 个测试全过。

- [ ] **Step 5: 提交**

```bash
git add internal/notify/notifier.go internal/notify/notifier_test.go
git commit -m "feat(notify): add Notifier interface, EventType constants, and global singleton"
```

---

### Task 2: 去重器

**Files:**
- Create: `internal/notify/dedup.go`
- Create: `internal/notify/dedup_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/notify/dedup_test.go`：

```go
package notify

import (
	"testing"
	"time"
)

func TestDedupBasic(t *testing.T) {
	t.Parallel()
	d := NewDedup(5 * time.Minute)

	if !d.Allow("acct1", EventRateLimited) {
		t.Fatal("first call should be allowed")
	}
	if d.Allow("acct1", EventRateLimited) {
		t.Fatal("second call within TTL should be denied")
	}
	if !d.Allow("acct1", EventOverloaded) {
		t.Fatal("different event type should be allowed")
	}
	if !d.Allow("acct2", EventRateLimited) {
		t.Fatal("different account should be allowed")
	}
}

func TestDedupTTLExpiry(t *testing.T) {
	t.Parallel()
	d := NewDedup(40 * time.Millisecond)

	if !d.Allow("acct", EventOverloaded) {
		t.Fatal("first call should be allowed")
	}
	time.Sleep(50 * time.Millisecond)
	if !d.Allow("acct", EventOverloaded) {
		t.Fatal("call after TTL should be allowed")
	}
}

func TestDedupConcurrent(t *testing.T) {
	t.Parallel()
	d := NewDedup(time.Minute)
	allowed := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() { allowed <- d.Allow("acct", EventBudgetBlocked) }()
	}
	count := 0
	for i := 0; i < 100; i++ {
		if <-allowed {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 allowed, got %d", count)
	}
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/notify/... -v -race -run TestDedup
```

期望：编译错误（NewDedup 未定义）。

- [ ] **Step 3: 实现 dedup.go**

新建文件 `internal/notify/dedup.go`：

```go
package notify

import (
	"fmt"
	"sync"
	"time"
)

// Dedup suppresses repeated notifications for the same account+event within a TTL window.
type Dedup struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

// NewDedup creates a Dedup with the given TTL.
func NewDedup(ttl time.Duration) *Dedup {
	return &Dedup{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// Allow returns true if the event should be sent (not seen within TTL), and records
// the current time. Returns false if the same account+event was seen within the TTL.
func (d *Dedup) Allow(account string, event EventType) bool {
	key := fmt.Sprintf("%s:%s", account, string(event))
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.entries[key]; ok && time.Since(last) < d.ttl {
		return false
	}
	d.entries[key] = time.Now()
	return true
}
```

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/notify/... -v -race -run TestDedup
```

期望：PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/notify/dedup.go internal/notify/dedup_test.go
git commit -m "feat(notify): add Dedup with 5-minute TTL suppression"
```

---

### Task 3: 配置持久化

**Files:**
- Create: `internal/notify/config.go`
- Create: `internal/notify/config_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/notify/config_test.go`：

```go
package notify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigMissingFile(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("expected nil for missing file, got %v", err)
	}
	if cfg.BotToken != "" || cfg.ChatID != "" {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := NotifyConfig{
		BotToken:       "bot123:token",
		ChatID:         "-1001234567890",
		EnableDisabled: true,
		EnableAnomaly:  true,
	}
	if err := SaveConfig(dir, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestSaveConfigPermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := SaveConfig(dir, NotifyConfig{BotToken: "x", ChatID: "y"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "notify.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file perm: got %o, want 0600", perm)
	}
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/notify/... -v -race -run TestLoadConfig\|TestSaveConfig
```

期望：编译错误（NotifyConfig 未定义）。

- [ ] **Step 3: 实现 config.go**

新建文件 `internal/notify/config.go`：

```go
package notify

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/binn/ccproxy/internal/fileutil"
)

const configFileName = "notify.json"

// NotifyConfig holds Telegram notification settings.
type NotifyConfig struct {
	BotToken       string `json:"bot_token"`
	ChatID         string `json:"chat_id"`
	EnableDisabled bool   `json:"enable_disabled"` // CategoryDisabled events
	EnableAnomaly  bool   `json:"enable_anomaly"`  // CategoryAnomaly events
}

// LoadConfig reads NotifyConfig from dataDir/notify.json.
// Returns an empty config (not an error) if the file does not exist.
func LoadConfig(dataDir string) (NotifyConfig, error) {
	path := filepath.Join(dataDir, configFileName)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NotifyConfig{}, nil
	}
	if err != nil {
		return NotifyConfig{}, err
	}
	var cfg NotifyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return NotifyConfig{}, err
	}
	return cfg, nil
}

// SaveConfig writes cfg to dataDir/notify.json atomically with 0600 permissions.
func SaveConfig(dataDir string, cfg NotifyConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(filepath.Join(dataDir, configFileName), data, 0600)
}
```

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/notify/... -v -race -run TestLoadConfig\|TestSaveConfig
```

期望：PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/notify/config.go internal/notify/config_test.go
git commit -m "feat(notify): add NotifyConfig load/save with atomic write and 0600 permissions"
```

---

### Task 4: TelegramNotifier

**Files:**
- Create: `internal/notify/telegram.go`
- Create: `internal/notify/telegram_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/notify/telegram_test.go`：

```go
package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeTelegramServer(t *testing.T, wantChatID string, responses []int) (*httptest.Server, *int) {
	t.Helper()
	callCount := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*callCount++
		idx := *callCount - 1
		statusCode := http.StatusOK
		if idx < len(responses) {
			statusCode = responses[idx]
		}
		if wantChatID != "" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["chat_id"] != wantChatID {
				t.Errorf("chat_id: got %q, want %q", body["chat_id"], wantChatID)
			}
		}
		w.WriteHeader(statusCode)
		w.Write([]byte(`{"ok":true}`))
	}))
	return srv, callCount
}

func newTestTelegramNotifier(srv *httptest.Server) *TelegramNotifier {
	n := NewTelegramNotifier(NotifyConfig{
		BotToken:       "test-token",
		ChatID:         "-100123",
		EnableDisabled: true,
		EnableAnomaly:  true,
	})
	n.baseURL = srv.URL
	n.client = srv.Client()
	return n
}

func TestTelegramNotifier_SendsMessage(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "-100123", []int{200})
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	err := n.Notify(context.Background(), Event{
		AccountName: "acct1",
		Type:        EventRateLimited,
		Detail:      "cooldown: 30s",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if *count != 1 {
		t.Errorf("expected 1 HTTP call, got %d", *count)
	}
}

func TestTelegramNotifier_CategoryDisabledFilter(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "", nil)
	defer srv.Close()

	n := NewTelegramNotifier(NotifyConfig{
		BotToken:       "tok",
		ChatID:         "-1",
		EnableDisabled: false, // disabled category OFF
		EnableAnomaly:  true,
	})
	n.baseURL = srv.URL
	n.client = srv.Client()

	// Disabled event → suppressed
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventAccountBanned})
	if *count != 0 {
		t.Errorf("expected 0 calls for suppressed category, got %d", *count)
	}

	// Anomaly event → sent
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventRateLimited})
	if *count != 1 {
		t.Errorf("expected 1 call for anomaly, got %d", *count)
	}
}

func TestTelegramNotifier_CategoryAnomalyFilter(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "", nil)
	defer srv.Close()

	n := NewTelegramNotifier(NotifyConfig{
		BotToken:       "tok",
		ChatID:         "-1",
		EnableDisabled: true,
		EnableAnomaly:  false, // anomaly category OFF
	})
	n.baseURL = srv.URL
	n.client = srv.Client()

	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventOverloaded})
	if *count != 0 {
		t.Errorf("expected 0 calls for suppressed anomaly, got %d", *count)
	}
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventAccountDisabled})
	if *count != 1 {
		t.Errorf("expected 1 call for disabled, got %d", *count)
	}
}

func TestTelegramNotifier_Dedup(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "", nil)
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventRateLimited})
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventRateLimited})
	if *count != 1 {
		t.Errorf("expected 1 call (dedup), got %d", *count)
	}
}

func TestTelegramNotifier_MessageContainsAccount(t *testing.T) {
	t.Parallel()
	var receivedText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		receivedText = body["text"]
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	_ = n.Notify(context.Background(), Event{
		AccountName: "my-account",
		Type:        EventAccountBanned,
		Detail:      "reason: platform_forbidden",
	})
	if !strings.Contains(receivedText, "my-account") {
		t.Errorf("message should contain account name, got: %q", receivedText)
	}
	if !strings.Contains(receivedText, "🔴") {
		t.Errorf("disabled event message should contain 🔴, got: %q", receivedText)
	}
}

func TestTelegramNotifier_UpstreamError(t *testing.T) {
	t.Parallel()
	srv, _ := makeTelegramServer(t, "", []int{500})
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	err := n.Notify(context.Background(), Event{AccountName: "a", Type: EventOverloaded})
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestFormatMessage_DisabledIcon(t *testing.T) {
	t.Parallel()
	msg := formatMessage(Event{AccountName: "a", Type: EventAccountDisabled, Detail: "x"})
	if !strings.HasPrefix(msg, "🔴") {
		t.Errorf("disabled event should start with 🔴, got: %q", msg)
	}
	if !strings.Contains(msg, time.Now().UTC().Format("2006-01-02")) {
		t.Errorf("message should contain today's date")
	}
}

func TestFormatMessage_AnomalyIcon(t *testing.T) {
	t.Parallel()
	msg := formatMessage(Event{AccountName: "a", Type: EventRateLimited, Detail: "x"})
	if !strings.HasPrefix(msg, "⚠️") {
		t.Errorf("anomaly event should start with ⚠️, got: %q", msg)
	}
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/notify/... -v -race -run TestTelegram\|TestFormat
```

期望：编译错误（TelegramNotifier 未定义）。

- [ ] **Step 3: 实现 telegram.go**

新建文件 `internal/notify/telegram.go`：

```go
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	telegramAPIBase = "https://api.telegram.org"
	dedupTTL        = 5 * time.Minute
	httpTimeout     = 10 * time.Second
)

// TelegramNotifier sends notifications via Telegram Bot API sendMessage.
type TelegramNotifier struct {
	cfg     NotifyConfig
	client  *http.Client
	dedup   *Dedup
	baseURL string // overridable for testing
}

// NewTelegramNotifier creates a TelegramNotifier from cfg.
func NewTelegramNotifier(cfg NotifyConfig) *TelegramNotifier {
	return &TelegramNotifier{
		cfg:     cfg,
		client:  &http.Client{Timeout: httpTimeout},
		dedup:   NewDedup(dedupTTL),
		baseURL: telegramAPIBase,
	}
}

// Notify sends an event if the category is enabled and not suppressed by dedup.
// Errors are logged as warnings; callers can ignore the returned error.
func (t *TelegramNotifier) Notify(ctx context.Context, event Event) error {
	cat := event.Type.Category()
	if cat == CategoryDisabled && !t.cfg.EnableDisabled {
		return nil
	}
	if cat == CategoryAnomaly && !t.cfg.EnableAnomaly {
		return nil
	}
	if !t.dedup.Allow(event.AccountName, event.Type) {
		return nil
	}
	if err := t.sendMessage(ctx, formatMessage(event)); err != nil {
		slog.Warn("telegram notify failed",
			"account", event.AccountName,
			"event", string(event.Type),
			"err", err,
		)
		return err
	}
	return nil
}

func (t *TelegramNotifier) sendMessage(ctx context.Context, text string) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage", t.baseURL, t.cfg.BotToken)
	body, _ := json.Marshal(map[string]string{
		"chat_id": t.cfg.ChatID,
		"text":    text,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API: status %d", resp.StatusCode)
	}
	return nil
}

func formatMessage(event Event) string {
	icon := "⚠️"
	if event.Type.Category() == CategoryDisabled {
		icon = "🔴"
	}
	return fmt.Sprintf(
		"%s [ccproxy] 账户异常通知\n\n账户：%s\n事件：%s\n详情：%s\n时间：%s UTC",
		icon,
		event.AccountName,
		eventTypeLabel(event.Type),
		event.Detail,
		time.Now().UTC().Format("2006-01-02 15:04:05"),
	)
}

func eventTypeLabel(e EventType) string {
	switch e {
	case EventAccountDisabled:
		return "账户被禁用 (连续401)"
	case EventAccountBanned:
		return "账户平台封禁"
	case EventRateLimited:
		return "真速率限制 (429)"
	case EventOverloaded:
		return "过载冷却 (529)"
	case EventTimeoutCooldown:
		return "超时阈值冷却"
	case EventBudgetBlocked:
		return "预算阻断 (Blocked)"
	default:
		return string(e)
	}
}
```

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/notify/... -v -race
```

期望：所有测试 PASS。

- [ ] **Step 5: 提交**

```bash
git add internal/notify/telegram.go internal/notify/telegram_test.go
git commit -m "feat(notify): add TelegramNotifier with category filter, dedup, and message formatting"
```

---

### Task 5: health.go 调用点

**Files:**
- Modify: `internal/loadbalancer/health.go`
- Create: `internal/loadbalancer/health_notify_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/loadbalancer/health_notify_test.go`：

```go
package loadbalancer

import (
	"context"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/notify"
)

// mockNotifier captures events for assertion.
type mockNotifier struct {
	events []notify.Event
}

func (m *mockNotifier) Notify(_ context.Context, e notify.Event) error {
	m.events = append(m.events, e)
	return nil
}

func withMockNotifier(t *testing.T) *mockNotifier {
	t.Helper()
	mock := &mockNotifier{}
	orig := notify.Global()
	notify.SetGlobal(mock)
	t.Cleanup(func() { notify.SetGlobal(orig) })
	return mock
}

func TestDisable_NotifiesAccountDisabled(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct1")
	h.Disable("consecutive_401")
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(mock.events))
	}
	if mock.events[0].Type != notify.EventAccountDisabled {
		t.Errorf("expected EventAccountDisabled, got %s", mock.events[0].Type)
	}
	if mock.events[0].AccountName != "acct1" {
		t.Errorf("expected account acct1, got %s", mock.events[0].AccountName)
	}
}

func TestDisable_NotifiesAccountBanned(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct2")
	h.Disable(PlatformBanReasonForbidden)
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(mock.events))
	}
	if mock.events[0].Type != notify.EventAccountBanned {
		t.Errorf("expected EventAccountBanned, got %s", mock.events[0].Type)
	}
}

func TestRecordError_429True_NotifiesRateLimited(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct3")
	headers := http.Header{
		"Anthropic-Ratelimit-Unified-5H-Reset": []string{time.Now().Add(time.Minute).Format(time.RFC3339)},
	}
	h.RecordError(context.Background(), 429, 0, headers)
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(mock.events))
	}
	if mock.events[0].Type != notify.EventRateLimited {
		t.Errorf("expected EventRateLimited, got %s", mock.events[0].Type)
	}
}

func TestRecordError_529_NotifiesOverloaded(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct4")
	h.RecordError(context.Background(), 529, 0, nil)
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(mock.events))
	}
	if mock.events[0].Type != notify.EventOverloaded {
		t.Errorf("expected EventOverloaded, got %s", mock.events[0].Type)
	}
}

func TestRecordTimeout_ThresholdReached_NotifiesTimeoutCooldown(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct5")
	ctx := context.Background()
	for i := 0; i < timeoutThreshold; i++ {
		h.RecordTimeout(ctx)
	}
	if len(mock.events) != 1 {
		t.Fatalf("expected 1 notification after threshold, got %d", len(mock.events))
	}
	if mock.events[0].Type != notify.EventTimeoutCooldown {
		t.Errorf("expected EventTimeoutCooldown, got %s", mock.events[0].Type)
	}
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/loadbalancer/... -v -race -run TestDisable_Notify\|TestRecordError_429\|TestRecordError_529\|TestRecordTimeout_Threshold
```

期望：编译通过，测试 FAIL（notify 调用未实现）。

- [ ] **Step 3: 修改 health.go**

在文件顶部 import 中加入 `"github.com/binn/ccproxy/internal/notify"` 和 `"context"`（后者已有）。

**修改 `Disable()` 方法**（当前第 287-291 行）：

将：
```go
func (h *AccountHealth) Disable(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disabled = true
	h.disabledReason = reason
}
```

改为：
```go
func (h *AccountHealth) Disable(reason string) {
	h.mu.Lock()
	h.disabled = true
	h.disabledReason = reason
	h.mu.Unlock()

	eventType := notify.EventAccountDisabled
	if IsPlatformBanReason(reason) {
		eventType = notify.EventAccountBanned
	}
	go notify.Global().Notify(context.Background(), notify.Event{
		AccountName: h.Name,
		Type:        eventType,
		Detail:      "reason: " + reason,
	})
}
```

**在 `RecordError()` 真 429 分支末尾**（`h.recordWindow(true)` 之后）加入：

```go
		notify.Global().Notify(ctx, notify.Event{
			AccountName: h.Name,
			Type:        notify.EventRateLimited,
			Detail:      fmt.Sprintf("cooldown: %s", cd),
		})
```

（`fmt` 已在 import 中。）

**在 `RecordError()` 529 分支末尾**（`h.consecutive529++` / `h.mu.Unlock()` 之后）加入：

```go
		notify.Global().Notify(ctx, notify.Event{
			AccountName: h.Name,
			Type:        notify.EventOverloaded,
			Detail:      fmt.Sprintf("cooldown: %s", cd),
		})
```

**在 `RecordTimeout()` 阈值触发分支**（`h.mu.Unlock()` 之后、`return` 之前）加入：

```go
		notify.Global().Notify(ctx, notify.Event{
			AccountName: h.Name,
			Type:        notify.EventTimeoutCooldown,
			Detail:      fmt.Sprintf("count: %d, cooldown: 2m", count),
		})
```

在此之前需在 `RecordTimeout` 中把 `h.timeoutCount` 赋给局部变量：

```go
	if h.timeoutCount >= timeoutThreshold && now.Sub(h.firstTimeoutAt) < healthWindowSize {
		count := h.timeoutCount
		h.mu.Unlock()
		observe.Logger(ctx).Warn("account cooldown: timeout threshold reached", "account", h.Name, "count", count)
		h.setCooldownWithTracking(2*time.Minute, "timeout_threshold")
		notify.Global().Notify(ctx, notify.Event{
			AccountName: h.Name,
			Type:        notify.EventTimeoutCooldown,
			Detail:      fmt.Sprintf("count: %d, cooldown: 2m", count),
		})
		return
	}
```

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/loadbalancer/... -v -race -run TestDisable_Notify\|TestRecordError_429\|TestRecordError_529\|TestRecordTimeout_Threshold
```

期望：PASS。

- [ ] **Step 5: 运行全量测试确认无回归**

```
go test ./internal/loadbalancer/... -race
```

期望：PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/loadbalancer/health.go internal/loadbalancer/health_notify_test.go
git commit -m "feat(notify): add notify calls to health.go Disable/RecordError/RecordTimeout"
```

---

### Task 6: budget.go 调用点

**Files:**
- Modify: `internal/loadbalancer/budget.go`
- Create: `internal/loadbalancer/budget_notify_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/loadbalancer/budget_notify_test.go`：

```go
package loadbalancer

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/notify"
)

func TestBudgetCheckStateChange_BlockedNotifies(t *testing.T) {
	mock := withMockNotifier(t) // reuse helper from health_notify_test.go
	bc := NewBudgetController("budget-acct")

	// Drive state into Blocked by injecting headers with high utilization
	headers := http.Header{
		"Anthropic-Ratelimit-Unified-5H-Utilization": []string{"0.98"},
		"Anthropic-Ratelimit-Unified-5H-Status":      []string{"allowed"},
		"Anthropic-Ratelimit-Unified-5H-Reset":       []string{time.Now().Add(time.Hour).Format(time.RFC3339)},
	}
	bc.UpdateFromHeaders(context.Background(), headers)

	// Give goroutine time to fire
	time.Sleep(20 * time.Millisecond)

	found := false
	for _, e := range mock.events {
		if e.Type == notify.EventBudgetBlocked && e.AccountName == "budget-acct" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EventBudgetBlocked notification, got %v", mock.events)
	}
}

func TestBudgetCheckStateChange_NormalDoesNotNotify(t *testing.T) {
	mock := withMockNotifier(t)
	bc := NewBudgetController("budget-acct2")

	headers := http.Header{
		"Anthropic-Ratelimit-Unified-5H-Utilization": []string{"0.50"},
		"Anthropic-Ratelimit-Unified-5H-Status":      []string{"allowed"},
		"Anthropic-Ratelimit-Unified-5H-Reset":       []string{time.Now().Add(time.Hour).Format(time.RFC3339)},
	}
	bc.UpdateFromHeaders(context.Background(), headers)
	time.Sleep(20 * time.Millisecond)

	for _, e := range mock.events {
		if e.Type == notify.EventBudgetBlocked {
			t.Errorf("unexpected EventBudgetBlocked for normal utilization")
		}
	}
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/loadbalancer/... -v -race -run TestBudgetCheckState
```

期望：FAIL（notify 调用未实现）。

- [ ] **Step 3: 修改 budget.go**

在文件顶部 import 中加入 `"github.com/binn/ccproxy/internal/notify"`。

**修改 `checkStateChange()` 方法**（在 `bc.lastState = current` 赋值后），在现有代码末尾添加：

```go
func (bc *BudgetController) checkStateChange(ctx context.Context) {
	current := bc.stateLocked()
	if current != bc.lastState {
		observe.Logger(ctx).Info("budget: state changed",
			"account", bc.name,
			"from", bc.lastState.String(),
			"to", current.String(),
		)
		bc.lastState = current
		if current == StateBlocked {
			name := bc.name
			util5h := bc.window5h.Utilization
			util7d := bc.window7d.Utilization
			go notify.Global().Notify(ctx, notify.Event{
				AccountName: name,
				Type:        notify.EventBudgetBlocked,
				Detail:      fmt.Sprintf("util_5h=%.0f%%, util_7d=%.0f%%", util5h*100, util7d*100),
			})
		}
	}
}
```

（`fmt` 已在 import 中。）

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/loadbalancer/... -race -run TestBudgetCheckState
```

期望：PASS。

- [ ] **Step 5: 运行全量测试确认无回归**

```
go test ./internal/loadbalancer/... -race
```

期望：PASS。

- [ ] **Step 6: 提交**

```bash
git add internal/loadbalancer/budget.go internal/loadbalancer/budget_notify_test.go
git commit -m "feat(notify): add notify call to budget.go checkStateChange on Blocked state"
```

---

### Task 7: Admin notify handlers

**Files:**
- Create: `internal/admin/notify_handlers.go`
- Create: `internal/admin/notify_handlers_test.go`

- [ ] **Step 1: 写失败测试**

新建文件 `internal/admin/notify_handlers_test.go`：

```go
package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/binn/ccproxy/internal/notify"
)

func TestHandleNotifyConfig_GET_MasksToken(t *testing.T) {
	h := newTestHandler(t)
	// Pre-save config so GET returns data
	if err := notify.SaveConfig(h.dataDir, notify.NotifyConfig{
		BotToken:       "bot:token1234",
		ChatID:         "-100999",
		EnableDisabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/notify/config", nil)
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	token, _ := result["bot_token"].(string)
	if !strings.HasPrefix(token, "****") {
		t.Errorf("bot_token should be masked, got %q", token)
	}
	if !strings.HasSuffix(token, "1234") {
		t.Errorf("masked token should end with last 4 chars, got %q", token)
	}
	if result["chat_id"] != "-100999" {
		t.Errorf("chat_id should be preserved, got %v", result["chat_id"])
	}
}

func TestHandleNotifyConfig_GET_EmptyConfig(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/api/notify/config", nil)
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHandleNotifyConfig_POST_SavesConfig(t *testing.T) {
	h := newTestHandler(t)
	body := map[string]interface{}{
		"bot_token":       "new-bot-token",
		"chat_id":         "-100111",
		"enable_disabled": true,
		"enable_anomaly":  false,
	}
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/notify/config", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	loaded, err := notify.LoadConfig(h.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BotToken != "new-bot-token" {
		t.Errorf("token not saved, got %q", loaded.BotToken)
	}
	if loaded.ChatID != "-100111" {
		t.Errorf("chat_id not saved, got %q", loaded.ChatID)
	}
	if !loaded.EnableDisabled {
		t.Error("enable_disabled should be true")
	}
}

func TestHandleNotifyConfig_POST_PreservesMaskedToken(t *testing.T) {
	h := newTestHandler(t)
	// Pre-save a token
	notify.SaveConfig(h.dataDir, notify.NotifyConfig{BotToken: "secret-token", ChatID: "-1"})

	// POST with masked token (user didn't change it)
	body := map[string]interface{}{
		"bot_token": "****oken",
		"chat_id":   "-1",
	}
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/notify/config", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	loaded, _ := notify.LoadConfig(h.dataDir)
	if loaded.BotToken != "secret-token" {
		t.Errorf("original token should be preserved, got %q", loaded.BotToken)
	}
}

func TestHandleNotifyTest_NoConfig(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/api/notify/test", nil)
	w := httptest.NewRecorder()
	h.HandleNotifyTest(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when not configured, got %d", w.Code)
	}
}
```

- [ ] **Step 2: 运行确认失败**

```
go test ./internal/admin/... -v -race -run TestHandleNotify
```

期望：编译错误（HandleNotifyConfig / HandleNotifyTest 未定义，h.dataDir 不存在）。

- [ ] **Step 3: 实现 notify_handlers.go**

新建文件 `internal/admin/notify_handlers.go`：

```go
package admin

import (
	"net/http"
	"strings"

	"github.com/binn/ccproxy/internal/notify"
)

// HandleNotifyConfig handles GET and POST /api/notify/config.
// GET returns the current config with bot_token masked.
// POST saves the config and reinitializes the global Notifier.
func (h *Handler) HandleNotifyConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := notify.LoadConfig(h.dataDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load config: "+err.Error())
			return
		}
		masked := cfg
		masked.BotToken = maskToken(cfg.BotToken)
		writeJSON(w, masked)

	case http.MethodPost:
		var body notify.NotifyConfig
		if !decodeBody(w, r, &body) {
			return
		}
		// Preserve existing token when the user submits the masked placeholder.
		if strings.HasPrefix(body.BotToken, "****") {
			existing, err := notify.LoadConfig(h.dataDir)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "load existing config: "+err.Error())
				return
			}
			body.BotToken = existing.BotToken
		}
		if err := notify.SaveConfig(h.dataDir, body); err != nil {
			writeError(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		if body.BotToken != "" && body.ChatID != "" {
			notify.SetGlobal(notify.NewTelegramNotifier(body))
		} else {
			notify.SetGlobal(&notify.NoopNotifier{})
		}
		writeJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleNotifyTest handles POST /api/notify/test.
// Sends a test Telegram message using the current saved config.
func (h *Handler) HandleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := notify.LoadConfig(h.dataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if cfg.BotToken == "" || cfg.ChatID == "" {
		writeError(w, http.StatusBadRequest, "telegram not configured")
		return
	}
	// Fresh notifier — no dedup history, so test message always goes through.
	n := notify.NewTelegramNotifier(cfg)
	if err := n.Notify(r.Context(), notify.Event{
		AccountName: "test",
		Type:        notify.EventAccountDisabled,
		Detail:      "this is a test notification from ccproxy admin",
	}); err != nil {
		writeError(w, http.StatusBadGateway, "telegram send failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// maskToken returns the token with all but the last 4 characters replaced by ****.
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 4 {
		return strings.Repeat("*", len(token))
	}
	return "****" + token[len(token)-4:]
}
```

- [ ] **Step 4: 运行确认通过**

```
go test ./internal/admin/... -v -race -run TestHandleNotify
```

期望：除 `TestHandleNotifyTest_NoConfig` 外全 PASS。`h.dataDir` 编译报错需等 Task 8 修改 handler.go 后解决。

> **注意：** Task 7 测试目前编译不通过（`h.dataDir` 字段未定义）。先让这些测试文件存在，继续 Task 8 后会全部通过。

- [ ] **Step 5: 提交**

```bash
git add internal/admin/notify_handlers.go internal/admin/notify_handlers_test.go
git commit -m "feat(admin): add notify config and test handlers"
```

---

### Task 8: 连线（server.go + handler.go）

**Files:**
- Modify: `internal/admin/handler.go`
- Modify: `internal/admin/handler_test.go`
- Modify: `internal/server/server.go`

- [ ] **Step 1: 修改 handler.go — 加入 dataDir 字段**

在 `internal/admin/handler.go` 的 `Handler` 结构体中加入 `dataDir string`：

```go
type Handler struct {
	balancer *loadbalancer.Balancer
	oauthMgr *oauth.Manager
	sessions *oauth.SessionStore
	cfg      *config.Config
	registry *config.AccountRegistry
	updater  *updater.Updater
	dataDir  string
}
```

修改 `NewHandler` 签名，在末尾加参数 `dataDir string`：

```go
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config, registry *config.AccountRegistry, upd *updater.Updater, dataDir string) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
		registry: registry,
		updater:  upd,
		dataDir:  dataDir,
	}
}
```

- [ ] **Step 2: 修改 handler_test.go — 更新 newTestHandler**

将 `newTestHandler` 最后一行从：
```go
return NewHandler(balancer, mgr, sessions, cfg, registry, nil)
```

改为：
```go
return NewHandler(balancer, mgr, sessions, cfg, registry, nil, dir)
```

- [ ] **Step 3: 修改 server.go — 初始化 notify 并注册路由**

在 `server.go` 的 import 中加入 `"github.com/binn/ccproxy/internal/notify"`。

在 `server.New()` 中，**在 `// 8. Create admin handler.` 之前**加入 notify 初始化：

```go
	// Initialize Telegram notifier from persisted config (if any).
	if notifyCfg, err := notify.LoadConfig("data"); err == nil && notifyCfg.BotToken != "" && notifyCfg.ChatID != "" {
		notify.SetGlobal(notify.NewTelegramNotifier(notifyCfg))
		slog.Info("telegram notifier initialized")
	}
```

修改 admin handler 创建语句，传入 `"data"`：

```go
	// 8. Create admin handler.
	adminHandler := admin.NewHandler(balancer, oauthMgr, oauthSessions, cfg, registry, upd, "data")
```

在 `server.go` 的路由注册部分（`/api/update/apply` 之后、`/admin/` 之前）加入：

```go
	mux.Handle("/api/notify/config", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleNotifyConfig))))
	mux.Handle("/api/notify/test", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleNotifyTest))))
```

- [ ] **Step 4: 运行全量测试确认通过**

```
go test ./... -race
```

期望：所有测试 PASS，无编译错误。

- [ ] **Step 5: 提交**

```bash
git add internal/admin/handler.go internal/admin/handler_test.go internal/server/server.go
git commit -m "feat(server): wire up notify initialization and admin API routes"
```

---

### Task 9: Admin UI

**Files:**
- Modify: `internal/admin/static/index.html`

- [ ] **Step 1: 在账户列表卡片后加入 Telegram 配置卡片**

在 `index.html` 中找到账户列表卡片的关闭标签（`  </div>` 紧跟 `</div>` 之前、container 闭合之前），插入以下卡片：

将：
```html
  </div>
</div>
```

（accounts card 的 `</div>` 紧接 container 的 `</div>`）改为：

```html
  </div>

  <div class="card" style="margin-top:16px;">
    <div class="card-header">
      <h2>Telegram 通知</h2>
    </div>
    <div style="padding:20px;">
      <div style="display:flex; flex-direction:column; gap:12px; max-width:480px;">
        <div>
          <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Bot Token</label>
          <input type="password" id="notify-bot-token" placeholder="1234567890:AAABBB…" autocomplete="off"
            style="width:100%; padding:6px 10px; background:var(--bg); border:1px solid var(--border); border-radius:4px; color:var(--text); font-size:13px; outline:none;" />
        </div>
        <div>
          <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Chat ID</label>
          <input type="text" id="notify-chat-id" placeholder="-1001234567890"
            style="width:100%; padding:6px 10px; background:var(--bg); border:1px solid var(--border); border-radius:4px; color:var(--text); font-size:13px; outline:none;" />
        </div>
        <div style="display:flex; flex-direction:column; gap:6px;">
          <label style="font-size:12px; color:var(--text-muted);">通知类别</label>
          <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
            <input type="checkbox" id="notify-disabled" />
            账户被禁用（连续401、平台封禁）
          </label>
          <label style="display:flex; align-items:center; gap:8px; font-size:13px; cursor:pointer;">
            <input type="checkbox" id="notify-anomaly" />
            其他异常（429 / 529 / 超时 / 预算阻断）
          </label>
        </div>
        <div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
          <button class="btn btn-accent" onclick="saveNotifyConfig()">保存配置</button>
          <button class="btn" onclick="testNotify()">发送测试消息</button>
          <span id="notify-status" style="font-size:12px;"></span>
        </div>
      </div>
    </div>
  </div>
</div>
```

- [ ] **Step 2: 在 `<script>` 标签内 `refresh()` 函数之前加入 notify JS 函数**

在 `async function refresh()` 之前插入：

```javascript
  async function loadNotifyConfig() {
    try {
      const data = await fetchJSON('/api/notify/config');
      document.getElementById('notify-bot-token').value = data.bot_token || '';
      document.getElementById('notify-chat-id').value = data.chat_id || '';
      document.getElementById('notify-disabled').checked = !!data.enable_disabled;
      document.getElementById('notify-anomaly').checked = !!data.enable_anomaly;
    } catch (e) {
      // silently ignore on load
    }
  }

  async function saveNotifyConfig() {
    var status = document.getElementById('notify-status');
    status.textContent = '保存中…';
    status.style.color = 'var(--text-muted)';
    try {
      await fetchJSON('/api/notify/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          bot_token: document.getElementById('notify-bot-token').value,
          chat_id: document.getElementById('notify-chat-id').value,
          enable_disabled: document.getElementById('notify-disabled').checked,
          enable_anomaly: document.getElementById('notify-anomaly').checked,
        }),
      });
      status.textContent = '✓ 保存成功';
      status.style.color = 'var(--success)';
    } catch (e) {
      status.textContent = '✗ 保存失败: ' + e.message;
      status.style.color = 'var(--danger)';
    }
  }

  async function testNotify() {
    var status = document.getElementById('notify-status');
    status.textContent = '发送中…';
    status.style.color = 'var(--text-muted)';
    try {
      await fetchJSON('/api/notify/test', { method: 'POST' });
      status.textContent = '✓ 测试消息已发送';
      status.style.color = 'var(--success)';
    } catch (e) {
      status.textContent = '✗ 发送失败: ' + e.message;
      status.style.color = 'var(--danger)';
    }
  }

```

- [ ] **Step 3: 在 `--- Init ---` 部分调用 loadNotifyConfig()**

将：
```javascript
  // --- Init ---
  refresh();
  setInterval(refresh, 30000);
```

改为：
```javascript
  // --- Init ---
  refresh();
  loadNotifyConfig();
  setInterval(refresh, 30000);
```

- [ ] **Step 4: 运行全量测试**

```
go test ./... -race
```

期望：PASS（index.html 变更不影响 Go 测试）。

- [ ] **Step 5: 手动验证 UI**

```
make run
```

打开 `http://localhost:<port>/admin/`，确认：
1. 页面底部出现"Telegram 通知"卡片
2. 输入 Bot Token 和 Chat ID，勾选类别，点"保存配置"，返回 `✓ 保存成功`
3. 再次刷新页面，Token 显示为 `****xxxx`，复选框状态保留
4. 点"发送测试消息"，若配置正确，Telegram 收到通知

- [ ] **Step 6: 提交**

```bash
git add internal/admin/static/index.html
git commit -m "feat(admin): add Telegram notification config card to dashboard"
```

---

## 自我审查结果

**Spec 覆盖：**
- ✅ 6 种事件类型（Task 1）
- ✅ 5 分钟去重（Task 2）
- ✅ data/notify.json 持久化（Task 3）
- ✅ TelegramNotifier 含 category filter（Task 4）
- ✅ 5 个调用点（Task 5, 6）
- ✅ Admin API GET/POST/test（Task 7, 8）
- ✅ 仪表盘卡片（Task 9）
- ✅ 全局单例读写锁保护（Task 1）
- ✅ 启动时初始化 notify（Task 8）

**无占位符、无 TBD、类型名称一致。**
