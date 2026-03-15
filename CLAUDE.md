# ccproxy — Claude Code 开发指南

## 项目概述

ccproxy 是一个用 Go 编写的单二进制 Claude API 代理。它汇集 Anthropic OAuth 订阅账户供团队共享，并通过八层伪装模拟 Claude CLI 身份（TLS 指纹、HTTP 头部、beta token、系统提示词、metadata.user_id、模型映射、thinking 块清理、body 消毒）。

模块路径：`github.com/binn/ccproxy`

详细架构文档请参阅 [docs/architecture.md](docs/architecture.md)。

## 构建命令

```bash
make build          # 编译到 bin/ccproxy
make test           # 运行所有测试（带 -race）
make run            # 构建并运行：./bin/ccproxy
make clean          # 清理 bin/ 和 data/
```

构建时嵌入版本号：

```bash
VERSION=1.0.0 make build
```

运行单个包的测试：

```bash
go test ./internal/disguise/... -v -race
```

## 关键目录

```
cmd/ccproxy/        入口点 (main.go)
internal/
  admin/            内嵌 HTML 仪表盘处理器和静态资源
  apierror/         共享 API 错误类型
  auth/             Bearer token 验证中间件（恒定时间比较）
  cli/              Cobra 命令：root（启动）、version
  config/           TOML 配置加载、校验、默认值、账户注册表
  disguise/         8 层 Claude CLI 伪装引擎
  fileutil/         文件 I/O 辅助工具（原子写入等）
  loadbalancer/     3 层负载均衡器、并发跟踪器、重试/故障转移、预算、健康检查、用量
  netutil/          SOCKS5 代理支持
  oauth/            PKCE 流程、AES-256-GCM 令牌存储、会话存储、Anthropic 提供者
  observe/          请求追踪上下文、按账户指标、StateProvider、定期日志
  proxy/            HTTP 代理处理器、SSE 流式传输、body 过滤器、错误映射
  ratelimit/        按 IP 限速中间件
  server/           HTTP 服务器设置（net/http mux、中间件组装）
  session/          会话亲和性与 TTL 管理
  tls/              TLS 指纹伪装
data/               运行时数据 — 不提交（.gitignore）
  accounts.json     动态账户注册表 (0600)
  oauth_tokens.json 加密的 OAuth 令牌 (0600)
config.toml.example 参考配置
```

## 重要模式

### 错误处理

- 始终用 `fmt.Errorf("context: %w", err)` 包装错误以保持错误链。
- CLI 命令返回 `error`；cobra 自动打印并以非零状态退出。
- HTTP 处理器使用 `internal/proxy/errors.go` 中的辅助函数生成 Anthropic 风格的 JSON 错误体。

### 配置

- `config.Load(path)` 一次性完成读取、解析、应用默认值、自动生成缺失凭据和校验。
- 如果 `admin_password` 为空或 `api_keys` 中没有启用的条目，`Load` 会自动生成加密安全的值，持久化到配置文件并打印到控制台。
- `base_url`、`request_timeout`、`max_concurrency` 是 `[server]` 下的全局设置。
- 账户**不在** TOML 中定义。它们通过管理仪表盘（"Add Claude"/"Remove" 按钮）动态管理，由 `config.AccountRegistry` 持久化到 `data/accounts.json`。
- `config.RuntimeAccount(acct)` 和 `config.RuntimeAccounts(registry)` 从全局设置 + 注册表条目构建 `AccountConfig` 结构体，供下游消费者（负载均衡器、代理、OAuth）使用。
- `AccountRegistry.SetOnChange(fn)` 在运行时将动态增删传播到负载均衡器和 OAuth 管理器。

### 并发

- `ConcurrencyTracker` 位于 `internal/loadbalancer/concurrency.go`，使用 `sync.Mutex` 和 `map[accountName]map[requestID]time.Time` 进行槽位追踪。无 Redis。
- 会话亲和性使用 `sync.Map`，键格式为 `{apiKeyName}:{sessionID}`，滑动 TTL 1 小时（每次命中重置）。
- OAuth 令牌存储使用按账户的互斥锁防止并发刷新竞争。

### 伪装引擎

激活条件：`!isClaudeCodeClient(request)`。所有账户使用 OAuth；对非 Claude Code 客户端始终应用伪装。TLS 指纹始终启用。

`internal/disguise/detector.go` 中的 `isClaudeCodeClient` 检测器使用门控评分系统：User-Agent 必须匹配 `claude-cli/x.x.x`（门控），然后对 `/v1/messages` 请求，4 个信号中至少 2 个匹配（X-App 头部、anthropic-beta token、metadata.user_id 模式、系统提示词 Dice 系数）。非 messages 路径仅需通过 UA 门控。

### OAuth

所有账户使用 OAuth 认证。Anthropic OAuth 常量（ClientID、AuthURL、TokenURL、RedirectURI、Scopes）硬编码在 `internal/oauth/provider.go` 中。

令牌按账户（非按提供者）存储在 `data/oauth_tokens.json`，权限 0600。加密密钥通过 Argon2 从 `hostname + username + machine-id` 派生——不存储任何口令。绝不记录或返回原始令牌值。

管理仪表盘位于 `/admin/`，提供 OAuth 账户管理的 Web UI：添加账户、删除账户、登录（PKCE 流程 + 手动粘贴授权码）、刷新和登出。PKCE 会话存储在内存中，TTL 10 分钟。账户增删触发 `AccountRegistry.onChange`，动态更新负载均衡器和 OAuth 管理器。

### SSE 流式传输

代理将上游响应作为原始字节流转发。令牌用量在流式传输期间从 `message_delta` 事件中提取。

## 测试方法

- TDD：先写测试，再实现直到通过。
- 每个非平凡包都有 `*_test.go` 文件，位于同包（白盒）或 `*_test` 包（黑盒）。
- 使用 `t.Run(name, ...)` 的表驱动测试处理多种输入变体。
- 在无共享可变状态的单元测试中使用 `t.Parallel()`。
- `-race` 标志为必选项；所有 CI 运行都使用它。

## 开发时的配置文件

复制并编辑 `config.toml.example`：

```bash
cp config.toml.example config.toml
```

然后运行：

```bash
make run
```
