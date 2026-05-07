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
make release VERSION=1.0.0  # 创建 git tag 并推送，触发 CI 发布
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
  cli/              Cobra 命令：root（启动）、version、upgrade
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
  updater/          OTA 自动升级引擎（GitHub Releases + go-selfupdate）
data/               运行时数据 — 不提交（.gitignore）
  accounts.json     动态账户注册表，含 owner 字段 (0600)
  oauth_tokens.json 加密的 OAuth 令牌 (0600)
  notify_*.json     按用户的 Telegram 通知配置 (0600)
config.toml.example 参考配置
```

## 重要模式

### 错误处理

- 始终用 `fmt.Errorf("context: %w", err)` 包装错误以保持错误链。
- CLI 命令返回 `error`；cobra 自动打印并以非零状态退出。
- HTTP 处理器使用 `internal/proxy/errors.go` 中的辅助函数生成 Anthropic 风格的 JSON 错误体。

### 配置

- `config.Load(path)` 一次性完成读取、解析、应用默认值、自动生成缺失凭据和校验。
- 如果 `admin_password` 为空或 `api_keys` 中没有启用的条目，`Load` 会自动生成加密安全的值，持久化到配置文件并打印到控制台。无 enabled key 时默认创建 3 个用户（alice/bob/charlie），各自有独立的 API key 和仪表盘密码。
- `base_url`、`request_timeout`、`max_concurrency` 是 `[server]` 下的全局设置。
- 账户**不在** TOML 中定义。它们通过管理仪表盘（"Add Claude"/"Remove" 按钮）动态管理，由 `config.AccountRegistry` 持久化到 `data/accounts.json`。每个账户有 `owner` 字段绑定到创建者的 API Key 名称。
- `config.RuntimeAccount(acct)` 和 `config.RuntimeAccounts(registry)` 从全局设置 + 注册表条目构建 `AccountConfig` 结构体，供下游消费者（负载均衡器、代理、OAuth）使用。
- `AccountRegistry.SetOnChange(fn)` 在运行时将动态增删传播到负载均衡器和 OAuth 管理器。

### 多用户模型

- **API Key = 用户**：每个 `APIKeyConfig` 有 `key`、`name`、`password`、`enabled` 四个字段。`password` 用于仪表盘登录（自动生成）。
- **两种角色**：
  - Admin（username=`admin`，password=`admin_password`）：只读全局视图，可见所有账户但不能操作，可触发更新。
  - 普通用户（username=`api_key.name`，password=`api_key.password`）：只能管理自己 `owner` 的账户。
- **Account.Owner**：每个账户绑定创建者。Admin 创建的或迁移的无主账户 owner 为空。
- **Telegram 通知分用户**：每用户独立配置（`data/notify_<username>.json`）。Admin 收所有异常，普通用户只收自己账户的 CategoryDisabled 事件（禁用/封禁）。
- **负载均衡不受影响**：所有 enabled 账户进入全局池共同调度，不区分 owner。

### 并发

- `ConcurrencyTracker` 位于 `internal/loadbalancer/concurrency.go`，使用 `sync.RWMutex` + per-account `sync.Mutex` 和 `map[accountName]map[requestID]time.Time` 进行槽位追踪（15 分钟陈旧清理）。无 Redis。
- 会话亲和性使用 `sync.Map`，键格式为 `{apiKeyName}:{sessionID}`，滑动 TTL 1 小时（每次命中重置）。
- OAuth 令牌存储使用按账户的互斥锁防止并发刷新竞争。

### 伪装引擎

激活条件：`!isClaudeCodeClient(request)`。所有账户使用 OAuth；对非 Claude Code 客户端始终应用伪装。TLS 指纹始终启用。

`internal/disguise/detector.go` 中的 `isClaudeCodeClient` 检测器使用门控评分系统：User-Agent 必须匹配 `claude-cli/x.x.x`（门控），然后对 `/v1/messages` 请求，5 个信号中至少 2 个匹配（X-App 头部、anthropic-beta token、metadata.user_id 模式、系统提示词 Dice 系数、Anthropic-Version 非空）。非 messages 路径仅需通过 UA 门控。

#### cch / 3hex 与版本白名单

ccproxy 自己计算 billing block 的 `cch`（keyed xxhash64，见 `cch.go`）和 `cc_version` 末尾的 `.3hex`（vM3 风格 SHA256，见 `three_hex.go`），不再依赖客户端原值。原因：一旦我们改了 body 的任何字节（UA、user_id、cc_version 三段号、metadata），客户端原 cch 就失效了；要么算对要么算错，没有"保留原值"这个安全选项。

`cch` 算法依赖 4 个硬编码的 64-bit `ATTEST_KEYS`（见 `cch.go`），这些 keys 是从 Claude Code binary `.rodata` 段抽出来的，跨版本会轮换。`internal/disguise/version_whitelist.go` 维护一张已验证版本表：每个条目都是抓包确认过 cch + 3hex 能用当前 `ATTEST_KEYS` 复现的 (UA, SDK, Runtime) 三元组。**所有出 ccproxy 的流量永远使用白名单最新版本**——包括默认值、自学习的 fp、`rebaseToWhitelist` 启动清洗，全部强制对齐。客户端实际版本不影响出口流量，自学习只吸收 OS/Arch（机器属性，与 cch 无关）。

##### 维护白名单（线下流程）

新版 Claude Code 发布后按这个流程验证 + 加入白名单。**严禁运行时自动跟版**——客户端自学习已被关闭，所有 UA 推进必须经过抓包验证。

1. **抓包**：用 `cccc-mitm` wrapper 跑几次真实请求，所有 `/v1/messages` 落盘到 `mitm-analysis/cch-probe/captured/`。覆盖几个场景就够：纯文本对话、工具调用、多轮对话、斜杠命令。

2. **跑验证脚本**：`python3 mitm-analysis/cch-probe/verify_captured.py`。它对每个样本独立验证两件事：
   - 用当前 `ATTEST_KEYS` 重算 cch，对比 wire 上的真值
   - 用当前 `isMetaTextPrefixes` 跑 vM3 模拟器算 3hex，对比 wire 上的真值

3. **判断结果**：
   - **全部通过** → 算法和前缀表完全匹配新版本。在 `version_whitelist.go` 末尾追加新条目 `{UserAgent, StainlessPackageVersion, StainlessRuntimeVersion}`，三元组从抓到的样本 `.meta` 文件直接抄。
   - **cch 失配** → `ATTEST_KEYS` 轮换了。先按 `cch.go` 文件头注释的 grep 流程从新版 binary 抽出新 V1..V4，更新 cch.go 常量，再重跑验证脚本。通过后再加白名单条目。
   - **3hex 失配** → 客户端引入了新的 isMeta 注入前缀（系统消息包装、模式切换横幅等）。看哪些样本失配，从 binary 找新前缀（`grep "isMeta:!0"` 周围 content 字符串），加到 `three_hex.go` 的 `isMetaTextPrefixes`，重跑验证。

4. **跑测试**：`go test ./internal/disguise/ -race -count=1`。`fresh_sample.bin` ground-truth 测试一定要过——它是回归保险。

5. **日志监控辅助判断**：线上 `BillingHeaderObserver` 记录每个 (UA_version, match_state) 一条 INFO 日志。某个新版本的 `mismatch` 持续上升就是该走上述流程的信号。但 ccproxy 自己的出口流量已经在用 ATTEST_KEYS 加白名单最新版本算 cch，**线上不会因为没及时跟版而立即坏掉**——只是冷启动账户的 UA 越来越像"装着旧 binary 的真客户端"，最终需要白名单刷新才不显得过时。

`mitm-analysis/cch-probe/` 下的 `cch_compute.py`、`verify_captured.py`、`fresh_sample.bin` 是这套流程的工具与基准样本，不要删。

### OAuth

所有账户使用 OAuth 认证。Anthropic OAuth 常量（ClientID、AuthURL、TokenURL、RedirectURI、Scopes）硬编码在 `internal/oauth/provider.go` 中。

令牌按账户（非按提供者）存储在 `data/oauth_tokens.json`，权限 0600。加密密钥通过 Argon2 从 `hostname + username + machine-id` 派生——不存储任何口令。绝不记录或返回原始令牌值。

管理仪表盘位于 `/admin/`，提供 OAuth 账户管理的 Web UI：添加账户、删除账户、登录（PKCE 流程 + 手动粘贴授权码）、刷新和登出。PKCE 会话存储在内存中，TTL 10 分钟。账户增删触发 `AccountRegistry.onChange`，动态更新负载均衡器和 OAuth 管理器。

### 自动升级

- `internal/updater/` 使用 `go-selfupdate` 检查 GitHub Releases 并自动替换二进制
- 后台定期检查（默认 1 小时），发现新版本后下载、校验 SHA256、原子替换、发送 SIGTERM 触发重启
- Docker 环境自动禁用（检测 `/.dockerenv`）
- `dev` 版本跳过后台检查
- CLI: `ccproxy upgrade [--check] [--force]`
- Admin API: `GET /api/update/status`, `POST /api/update/check`, `POST /api/update/apply`

### SSE 流式传输

代理将上游响应作为原始字节流转发。令牌用量从 `message_start`（input tokens）和 `message_delta`（output tokens）事件中提取。SSE 缓冲区最大 1MB，使用 `sync.Pool` 复用 buffer。

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
