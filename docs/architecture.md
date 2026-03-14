# ccproxy 架构文档

## 概述

ccproxy 是一个用 Go 编写的单二进制 Claude API 反向代理。它将多个 Anthropic OAuth 订阅账号池化，供团队共享使用，并通过六层伪装引擎让上游流量看起来像合法的 Claude Code 请求。

**核心能力：**
- 多账号池化 + 会话亲和性负载均衡
- 六层 Claude CLI 身份伪装
- OAuth PKCE 认证 + 加密令牌存储
- 自适应背压与双窗口预算追踪
- Web 管理仪表盘
- TOML 配置自动生成凭据

---

## 系统架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                        客户端请求                                │
│               Authorization: Bearer <api_key>                    │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                     HTTP Server (net/http)                        │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              全局中间件（由外到内）                            │ │
│  │  recoveryMiddleware → requestLogMiddleware → ServeMux        │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
│  路由组：                                                         │
│  ┌──────────────────┬──────────────────┬─────────────────────┐  │
│  │ /v1/messages     │ /admin/ /api/*   │ /health             │  │
│  │ Bearer Auth      │ RateLimit+Basic  │ 无认证               │  │
│  │ → ProxyHandler   │ → AdminHandler   │ → 200 "ok"          │  │
│  └──────────────────┴──────────────────┴─────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────┘
                            │ (/v1/messages)
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Proxy Handler                               │
│                                                                   │
│  1. 读取请求体（8MB 限制）                                        │
│  2. 轻量解析：model, stream, metadata.user_id                    │
│  3. 提取 session ID → 组合 session key                           │
│  4. 注入 RequestContext（request_id, api_key_name）              │
│  5. ExecuteWithRetry → 负载均衡 + 重试/切换                      │
│  6. 返回上游响应（SSE 流转发 或 JSON 直传）                       │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    执行流水线 (doRequest)                         │
│                                                                   │
│  ┌─ SOCKS5 代理注入（按实例配置）                                 │
│  ├─ OAuth 令牌获取（自动刷新，≤60s 过期触发）                     │
│  ├─ 伪装引擎应用（非 CC 客户端 → 全量伪装）                      │
│  ├─ URL 修改（?beta=true）                                       │
│  ├─ TLS 指纹伪造传输层发送                                        │
│  └─ 返回上游响应                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 启动流程

```
cmd/ccproxy/main.go
  → cli.Execute()
    → cobra rootCmd.RunE
      → config.SetupLoggingDefaults()   // 预设日志
      → config.Load(cfgFile)            // 读取/生成配置 + 自动生成凭据
      → server.New(cfg)                 // 装配所有组件（见下）
      → 注册 SIGINT/SIGTERM 信号处理
      → srv.Start()                     // 开始监听
```

### server.New() 装配顺序

| 步骤 | 组件 | 说明 |
|------|------|------|
| 1 | `InstanceRegistry` | 从 `data/instances.json` 加载实例列表 |
| 2 | `ConcurrencyTracker` + `Balancer` | 并发追踪器 + 三层负载均衡器 |
| 3 | `DisguiseEngine` | 六层伪装引擎 + 会话掩码清理 |
| 4 | `TokenStore` + `OAuthManager` | AES-256-GCM 加密令牌存储 + OAuth 管理器 |
| 5 | `SessionStore` | PKCE 会话存储（10 分钟 TTL） |
| 5b | `UsageFetcher` | 自适应背压用量抓取器 |
| 6 | `registry.SetOnChange` | 注册动态实例变更回调 |
| 7 | `ProxyHandler` | 代理请求处理器 |
| 8 | `AdminHandler` | 管理面板处理器 |
| 9 | HTTP Mux + 中间件 | 路由注册 + 中间件挂载 |

---

## 核心子系统

### 1. 负载均衡器 (internal/loadbalancer)

#### 三层选择算法

```
L1 Pool — SRE 节流 + 利用率延迟 + 等待队列
  │
  ▼
L2 Sticky — 会话亲和（1h TTL），预算感知并发
  │
  ▼
L3 Score — 负载感知选择 + 预算状态过滤
```

**L1 Pool 级背压 (`PoolThrottle`)**
- SRE 自适应节流公式：`P(reject) = max(0, (requests - K*accepts) / (requests + 1))`，K=2.0
- 利用率延迟：池平均利用率 >50% 时，注入二次方延迟（最高 5s，±15% 抖动）
- 等待队列：被节流的请求进入有界队列等待（默认 30s，流式 10s）

**L2 会话亲和 (`Balancer.sessions`)**
- key = `{apiKeyName}:{sessionID}`，TTL = 1 小时
- 用 `sync.Map` 存储，60 秒清理一次过期条目
- 检查实例健康和预算动态并发后再复用

**L3 Score 选择**
- 过滤条件：排除已排除实例 → 排除不可用实例（禁用/冷却中）→ 排除 Blocked/StickyOnly 预算状态 → 排除满载实例
- 评分公式：`score = errorRate*0.3 + normalizedLatency*0.2 + loadRate/100*0.2 + maxUtil*0.3`
  - `errorRate`：5 分钟滑动窗口错误率
  - `normalizedLatency`：快 EMA / 慢 EMA（α=0.5 / α=0.1），归一化到 0-1
  - `loadRate`：当前并发 / 动态最大并发
  - `maxUtil`：max(5h 利用率, 7d 利用率)
- 按分数升序排序，分数相同按最近使用时间升序（LRU）

#### 重试与故障转移 (`ExecuteWithRetry`)

| HTTP 状态码 | 动作 | 说明 |
|------------|------|------|
| 200-399 | 成功 | 绑定会话、上报健康 |
| 400 | `ReturnToClient` | 直接返回给客户端 |
| 401 | `FailoverImmediate` | 触发令牌刷新 → 切换实例 |
| 403 | `FailoverImmediate` | 禁用实例 → 切换 |
| 429 | `FailoverImmediate` | 真 429（有 reset headers）vs 假 429（短冷却） |
| 500-504 | `RetryThenFailover` | 同实例重试 3 次 → 切换 |
| 529 | `FailoverImmediate` | 连续 529 ≥2 次则停止重试 |

- 最大实例切换次数：3
- 同实例最大重试次数：3
- 重试退避：300ms 基础，指数增长，上限 3s
- 总超时：10 秒

#### 签名错误三阶段重试

代理层对 400 状态码检测签名错误（`IsSignatureError`），执行三阶段降级：
1. **Stage 0**：发送原始请求体
2. **Stage 1**：过滤 thinking blocks 后重试
3. **Stage 2**：过滤所有签名敏感块（thinking + tool）后重试

#### 健康追踪 (`AccountHealth`)

每个实例独立追踪：
- **冷却机制**：429 → 30s/5s，529 → 60s+随机抖动，401 → 30s
- **禁用条件**：403 立即禁用，连续 401 ≥3 次在 5 分钟内禁用
- **延迟 EMA**：慢 α=0.1，快 α=0.5，无锁 CAS 更新
- **滑动窗口**：5 分钟窗口，最大 1000 条目，写入时裁剪

#### 双窗口预算控制 (`BudgetController`)

追踪 Anthropic 统一限速的两个窗口（5h 和 7d）：

| 利用率范围 | 调度状态 | 行为 |
|-----------|---------|------|
| < normalThreshold (0.60) | `Normal` | 正常调度 |
| normal ~ danger | `StickyOnly` | 仅服务粘性会话 |
| ≥ dangerThreshold (0.80) | `Blocked` | 不调度任何请求 |

- 连续真 429 会下移阈值（每次 -0.03，最大 -0.15），5 分钟无 429 后逐步恢复
- 动态并发调整：利用率 <50% → 8，<70% → 5，<85% → 3，≥85% → 1

**数据来源：**
- 响应头 `anthropic-ratelimit-unified-{5h,7d}-{utilization,status,reset}`
- `UsageFetcher` 后台定时拉取 API（数据陈旧时触发）

### 2. 伪装引擎 (internal/disguise)

#### 客户端检测 (`IsClaudeCodeClient`)

分层验证：
1. **门控**：User-Agent 必须匹配 `claude-cli/x.x.x`（必须通过）
2. **非 messages 路径**：UA 匹配即通过
3. **Haiku 探针**：`max_tokens=1 + haiku + !stream` → 直接通过
4. **Messages 路径**：需要 4 个信号中的 ≥2 个：
   - `X-App: cli`
   - `Anthropic-Beta` 包含 `claude-code`
   - `metadata.user_id` 匹配 `user_{hex64}_account__session_{uuid}` 格式
   - 系统提示词前缀匹配或 Dice 系数 ≥ 0.5

#### 八层伪装流水线（非 CC 客户端）

| 层 | 文件 | 功能 |
|----|------|------|
| 1 | `tls/fingerprint.go` | TLS 指纹伪造（Node.js 20.x + OpenSSL 3.x） |
| 2 | `headers.go` | HTTP 头替换：User-Agent, X-Stainless-*, X-App（每实例指纹） |
| 3 | `beta.go` | anthropic-beta 令牌组合（按模型和工具场景） |
| 4 | `engine.go` | 系统提示词注入 Claude Code 身份声明 |
| 5 | `metadata.go` | 生成/重写 `metadata.user_id`（含会话掩码） |
| 6 | `models.go` | 模型 ID 正规化（短名称 → 完整版本号） |
| 7 | `thinking.go` | 清理 thinking blocks 的 `cache_control` |
| 8 | `engine.go` | 请求体消毒：注入空 tools 数组，删除 temperature/tool_choice |

**CC 客户端轻量处理：** 仅补充 beta header + 重写 `metadata.user_id`（会话掩码）

**会话掩码 (`SessionMaskStore`)：** 每实例生成一个 UUID 掩码 session，替换 `user_id` 中的 session 部分，防止跨用户关联。定时清理过期掩码。

**每实例指纹 (`FingerprintStore`)：** 从 `data/fingerprints.json` 加载每实例的 User-Agent、Stainless OS/Arch 等信息，让不同实例呈现不同的客户端特征。

#### 响应处理

- 模型 ID 反正规化：响应中的完整版本号 → 客户端请求的短名称

### 3. OAuth 管理 (internal/oauth)

#### 组件

| 组件 | 说明 |
|------|------|
| `AnthropicProvider` | 封装 Anthropic OAuth 常量（ClientID, AuthURL, TokenURL 等） |
| `TokenStore` | AES-256-GCM 加密存储，key 由 Argon2 派生自 hostname+username+machine-id |
| `Manager` | 令牌生命周期管理，per-instance mutex 防并发刷新竞争 |
| `SessionStore` | PKCE 会话内存存储，10 分钟 TTL |
| `PKCE` | 生成 code_verifier/code_challenge (S256) |

#### 令牌生命周期

```
浏览器 PKCE 登录                   自动刷新
       │                              │
       ▼                              ▼
ExchangeAndSave()             StartAutoRefresh (5 min tick)
       │                              │
       ▼                              ▼
 TokenStore.Save()            检查 ExpiresAt < 60s
       │                              │
       ▼                              ▼
  加密写入磁盘                  refreshToken() → 双重检查锁
                                       │
                                       ▼
                               provider.RefreshToken()
                                       │
                                       ▼
                                TokenStore.Save()
```

- `GetValidToken`：加载令牌 → 距过期 >60s 直接返回 → 否则触发刷新
- `MarkTokenExpired`：立即标记过期（401 时调用）
- `ForceRefreshBackground`：后台 goroutine 刷新

#### 加密

- 算法：AES-256-GCM
- 密钥派生：Argon2id（password=hostname+username+machineID, salt=hostname+username）
- 存储路径：`data/oauth_tokens.json`，权限 0600
- 原子写入：通过 `fileutil.AtomicWriteFile`

### 4. TLS 指纹伪造 (internal/tls)

- 使用 `refraction-networking/utls` 库
- 模拟 Node.js 20.x + OpenSSL 3.x 的 TLS ClientHello
- 特征：
  - TLS 1.2/1.3 双版本支持
  - X25519 + P-256/384/521 曲线
  - ALPN: `http/1.1`
  - PSK DHE 密钥交换
- 每连接创建新 spec（避免 utls 内部状态复用导致的握手失败）
- 按 proxy URL 分组连接池（直连和各 SOCKS5 代理各维护独立连接池）

### 5. 配置管理 (internal/config)

#### 配置加载 (`config.Load`)

```
ensureConfigFile() → 不存在则创建默认配置
  → ReadFile + TOML 解析
    → applyDefaults() → 填充零值默认值
      → SetupLogging() → 配置 slog
        → autoGenerate() → 自动生成 admin_password 和 api_key
          → Validate() → 业务规则校验
            → printGeneratedCredentials()
```

#### 实例注册表 (`InstanceRegistry`)

- 实例**不在** TOML 配置中定义
- 通过管理面板动态添加/删除，持久化到 `data/instances.json`
- `SetOnChange(fn)` 注册回调，变更时通知 Balancer 和 OAuthManager
- `RuntimeInstances()` 将注册表条目 + 全局配置合并为 `InstanceConfig`

#### 配置变更

TOML 配置在启动时一次性加载，变更需要重启生效。代码中存在 `config.Watch` 函数（基于 fsnotify），但当前未被调用。

动态变更通过管理面板实现：实例的增删通过 `InstanceRegistry` + `onChange` 回调即时生效，无需重启。

### 6. 可观测性 (internal/observe)

#### 请求追踪 (`RequestContext`)

通过 `context.Value` 传递：
- `RequestID`：UUID
- `APIKeyName`：使用的 API key 名称
- `SessionKey`：会话键

`observe.Logger(ctx)` 返回带 `request_id` 和 `api_key` 的 slog.Logger。

#### 全局指标 (`Metrics`)

原子计数器，无锁：

| 指标 | 说明 |
|------|------|
| `RequestsTotal` | 总请求数 |
| `RequestsThrottled` | 被节流请求数 |
| `RequestsQueued` | 进入等待队列数 |
| `RequestsSuccess` | 成功请求数 |
| `RequestsError` | 失败请求数 |
| `RetriesTotal` | 重试次数 |
| `FailoversTotal` | 故障转移次数 |
| `Instances429` | 429 响应次数 |
| `Instances529` | 529 响应次数 |

每 5 分钟输出一次摘要日志。

### 7. 管理面板 (internal/admin)

- 嵌入式单页 HTML，无外部资源依赖
- HTTP Basic Auth 保护（任意用户名 + admin_password）
- 全局 per-IP 限速

**API 端点：**

| 端点 | 方法 | 功能 |
|------|------|------|
| `/admin/` | GET | 仪表盘页面 |
| `/api/instances` | GET | 实例列表（含健康和负载信息） |
| `/api/instances/add` | POST | 添加新实例 |
| `/api/instances/remove` | POST | 删除实例 |
| `/api/instances/proxy` | POST | 更新实例代理设置 |
| `/api/sessions` | GET | 活跃会话列表 |
| `/api/oauth/login/start` | POST | 启动 OAuth PKCE 登录 |
| `/api/oauth/login/complete` | POST | 完成 OAuth 登录 |
| `/api/oauth/refresh` | POST | 强制刷新令牌 |
| `/api/oauth/logout` | POST | 登出并删除令牌 |

### 8. SSE 流转发 (internal/proxy/streaming.go)

- `bufio.Scanner` 逐行扫描，缓冲区初始 64KB，最大 1MB（支持 thinking blocks 长行）
- `sseBufPool` (`sync.Pool`) 复用 `bytes.Buffer` 减少 GC 压力
- 逐事件解析：`event:` 行、`data:` 行、空行（事件边界），每个事件 flush 一次
- 从 `message_start` 提取 input tokens，从 `message_delta` 提取 output tokens
- `message_start` 中的 model ID 同步反向映射（`bytes.Replace`，精确替换 1 次）
- `loggingResponseWriter` 实现 `http.Flusher` 接口，确保实时推送
- 客户端断连后优雅退出，不报错

---

## 中间件链

### /v1/messages 路由
```
recoveryMiddleware
  → requestLogMiddleware
    → auth.Middleware（Bearer token 常量时间比较）
      → proxy.Handler.ServeHTTP
```

### /admin/ 和 /api/* 路由
```
recoveryMiddleware
  → requestLogMiddleware
    → ratelimit.Middleware（per-IP 令牌桶）
      → basicAuth（admin_password 常量时间比较）
        → admin.Handler.*
```

---

## 数据流

### 请求处理完整流程

```
客户端 POST /v1/messages
  │
  ├─ auth.Middleware 验证 Bearer token
  │
  ├─ ProxyHandler:
  │   ├─ 读取并解析请求体
  │   ├─ 提取 session key
  │   └─ 注入 RequestContext
  │
  ├─ ExecuteWithRetry:
  │   ├─ L1: PoolThrottle 检查
  │   ├─ L2: 会话亲和查找
  │   ├─ L3: Score 选择实例
  │   └─ doRequest:
  │       ├─ 注入 SOCKS5 代理（如有）
  │       ├─ 获取 OAuth token
  │       ├─ 伪装引擎处理
  │       ├─ TLS 指纹传输层发送
  │       └─ 返回上游响应
  │
  ├─ 成功：绑定会话、上报健康、更新预算
  │
  └─ 转发响应（SSE 流 或 JSON 直传）
```

### 实例动态变更传播

```
管理面板添加/删除实例
  → InstanceRegistry.Add/Remove
    → 持久化到 data/instances.json
    → onChange 回调触发:
        ├─ cfg.RuntimeInstances(registry) → 构建新实例列表
        ├─ balancer.UpdateInstances()     → 更新负载均衡器（保留已有健康状态）
        └─ oauthMgr.UpdateInstances()    → 更新 OAuth 管理器（添加新 mutex）
```

### 配置变更

TOML 配置在启动时加载，变更需重启。实例变更通过管理面板即时生效（见上方实例动态变更传播）。

---

## 并发模型

| 组件 | 同步机制 | 说明 |
|------|---------|------|
| `ConcurrencyTracker` | `sync.Mutex` | `map[instance]map[requestID]time.Time` 槽位追踪 |
| 会话亲和 | `sync.Map` | 无锁读写适合高并发读 |
| `AccountHealth` | `sync.RWMutex` + `atomic.Int64` | 冷却/禁用用 RWMutex，延迟 EMA 用无锁 CAS |
| `BudgetController` | `sync.RWMutex` | 双窗口状态保护 |
| `TokenStore` | `sync.RWMutex` + `sync.Once` | 缓存读写 + 单次初始化 |
| OAuth 刷新 | per-instance `sync.Mutex` | 防止并发刷新竞争 |
| `PoolThrottle` | `sync.Mutex` | 滑动窗口计数 |
| TLS 连接池 | `sync.Mutex` | per-proxy Transport 缓存 |
| `Balancer.instances` | `sync.RWMutex` | 实例列表热更新 |

---

## 后台 Goroutine

| Goroutine | 间隔 | 触发方 | 功能 |
|-----------|------|-------|------|
| 会话清理 | 60s | `Balancer.StartCleanup` | 清理过期会话和陈旧并发槽位 |
| 健康状态持久化 | 定时 | `Balancer.StartPersistence` | 持久化健康状态到磁盘 |
| OAuth 自动刷新 | 5min | `OAuthManager.StartAutoRefresh` | 检查令牌过期并刷新 |
| PKCE 会话清理 | 1min | `SessionStore.StartCleanup` | 清理过期 PKCE 会话 |
| 会话掩码清理 | 1min | `DisguiseEngine.StartSessionCleanup` | 清理过期掩码 |
| 用量抓取 | 定时 | `UsageFetcher.StartBackground` | 拉取实例用量数据更新预算 |
| 指标日志 | 5min | `Metrics.StartPeriodicLog` | 输出指标摘要日志 |

所有后台 goroutine 通过 `context.WithCancel` 统一管理，Server.Shutdown 时取消。

---

## 存储层

| 文件 | 权限 | 格式 | 内容 |
|------|------|------|------|
| `config.toml` | 0600 | TOML | 服务器配置、API keys（启动时加载，变更需重启） |
| `data/instances.json` | 0600 | JSON | 动态实例注册表 |
| `data/oauth_tokens.json` | 0600 | JSON | AES-256-GCM 加密的 OAuth 令牌 |
| `data/fingerprints.json` | - | JSON | 每实例 TLS/HTTP 指纹 |
| `data/health_state.json` | - | JSON | 持久化的健康状态 |

所有文件写入使用 `fileutil.AtomicWriteFile`（写临时文件 → rename），保证原子性。

---

## 外部依赖

| 依赖 | 版本 | 用途 |
|------|------|------|
| `github.com/BurntSushi/toml` | v1.6.0 | TOML 配置解析 |
| `github.com/fsnotify/fsnotify` | v1.9.0 | 配置文件变更监听（已实现但未启用） |
| `github.com/google/uuid` | v1.6.0 | UUID 生成（request ID, session mask） |
| `github.com/refraction-networking/utls` | v1.8.2 | TLS 指纹伪造（uTLS） |
| `github.com/spf13/cobra` | v1.10.2 | CLI 框架 |
| `golang.org/x/crypto` | v0.48.0 | Argon2 密钥派生 |
| `golang.org/x/net` | v0.51.0 | SOCKS5 代理支持 |
| `golang.org/x/sync` | v0.20.0 | 同步原语扩展 |

---

## 安全设计

- **API key 验证**：常量时间比较（`crypto/subtle.ConstantTimeCompare`）
- **Admin 密码验证**：同上
- **OAuth 令牌存储**：AES-256-GCM 加密，密钥由 Argon2id 从机器特征派生
- **文件权限**：敏感文件 0600
- **原子写入**：防止部分写入导致的数据损坏
- **限速**：Admin 路由 per-IP 令牌桶限速
- **会话掩码**：重写 `user_id` 防止跨用户关联
- **令牌不外泄**：不记录、不返回原始 OAuth token 值
- **CSRF 防护**：PKCE 登录的 state 参数用 `subtle.ConstantTimeCompare` 验证
- **限速 IP 提取**：基于 `RemoteAddr`，不信任 `X-Forwarded-For`，防止 IP 伪造
