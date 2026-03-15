# ccproxy

一个单二进制 Claude API 代理，汇集 Anthropic OAuth 订阅账户供小团队共享，通过完整的 Claude CLI 身份伪装使上游流量看起来像合法的 Claude Code 请求。

## 功能特性

- 完整 8 层 Claude CLI 伪装：TLS 指纹、HTTP 头部、anthropic-beta token、系统提示词注入、metadata.user_id 生成、模型 ID 映射、thinking 块清理、body 消毒
- 多账户负载均衡，支持会话亲和性、自适应背压和负载感知调度
- OAuth PKCE 流程，加密令牌存储和自动刷新
- 基于 Web 的管理仪表盘，用于账户管理和 OAuth 登录
- TOML 配置，自动生成缺失凭据
- 可观测性：请求追踪、指标和定期日志
- 单二进制，无外部依赖

## 快速开始

**构建：**

```bash
make build
# 输出：bin/ccproxy
```

**运行：**

```bash
./bin/ccproxy
```

首次启动时，ccproxy 会自动生成 `config.toml`（如缺失）、API 密钥和管理密码，并打印到控制台。

**添加账户：** 打开 `http://<host>:<port>/admin/`，使用"Add Claude"按钮。在仪表盘中通过 OAuth 登录流程认证每个账户。

代理默认监听 `http://0.0.0.0:3000`。将你的 Claude 兼容客户端指向此地址，使用生成的 API 密钥作为 Bearer token。

## 配置参考

配置从 `config.toml` 读取（使用 `-c <path>` 覆盖）。修改后需要重启才能生效。

### `[server]`

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `host` | `0.0.0.0` | 监听地址 |
| `port` | `3000` | 监听端口 |
| `admin_password` | （自动生成） | `/admin/` 和 `/api/*` 路由的 Basic Auth 密码 |
| `rate_limit` | `60` | 管理路由每 IP 每分钟最大请求数 |
| `base_url` | `https://api.anthropic.com` | 上游 Anthropic API 基础 URL |
| `request_timeout` | `300` | 每请求超时（秒） |
| `max_concurrency` | `5` | 每账户并发限制 |
| `log_level` | `info` | 日志级别（`debug`、`info`、`warn`、`error`） |
| `log_format` | `text` | 日志格式（`text` 或 `json`） |

### `[[api_keys]]`

下游客户端发送的 `Authorization: Bearer <key>` 凭据。

| 字段 | 说明 |
|------|------|
| `key` | Bearer token 值 |
| `name` | 日志中使用的可读标签 |
| `enabled` | 设为 `false` 可禁用而不删除 |

如果没有配置已启用的密钥，启动时会自动生成一个。

### 账户

账户**不在** TOML 配置文件中定义。它们通过管理仪表盘（"Add Claude"/"Remove"按钮）动态管理，持久化到 `data/accounts.json`。

### 示例

```toml
[server]
host = "0.0.0.0"
port = 3000
base_url = "https://api.anthropic.com"
request_timeout = 300
max_concurrency = 5

[[api_keys]]
key = "sk-ccproxy-001"
name = "dev-team"
enabled = true
```

## CLI 用法

```
ccproxy                   启动代理服务器（前台运行）
ccproxy version           打印版本号
ccproxy -c <path>         使用指定配置文件（默认：config.toml）
```

## 架构概览

```
ccproxy（单二进制）
├── CLI 层 (cobra)
│   └── start（根命令）、version
├── HTTP 服务器 (net/http ServeMux)
│   ├── /v1/messages         代理处理器（SSE 流式传输）
│   ├── /admin/              内嵌 HTML 仪表盘
│   ├── /api/*               账户管理和 OAuth API
│   └── /health              健康检查
├── 核心服务
│   ├── Auth Guard           Bearer token 验证（恒定时间比较）
│   ├── Rate Limiter         管理路由按 IP 限速
│   ├── Proxy Handler        请求转发和 SSE 流式传输
│   ├── Disguise Engine      8 层 Claude CLI 伪装
│   ├── Load Balancer        L1 Pool 节流 → L2 Sticky 亲和 → L3 Score 评分
│   ├── Concurrency Tracker  按账户槽位管理（内存中）
│   ├── Budget Controller    双窗口（5h/7d）自适应背压
│   ├── OAuth Manager        PKCE 流程、AES-256-GCM 令牌存储、自动刷新
│   └── Observability        请求追踪、指标、定期日志
└── 存储层
    ├── JSON 文件            加密的 OAuth 令牌 (data/oauth_tokens.json)
    ├── JSON 文件            动态账户注册表 (data/accounts.json)
    └── TOML 文件            配置（启动时读取）
```

**负载均衡器**使用 3 层选择算法：
1. **L1 Pool**：SRE 自适应节流 + 基于利用率的延迟 + 等待队列
2. **L2 Sticky**：会话亲和性（1h 滑动 TTL）+ 预算感知并发
3. **L3 Score**：`errorRate*0.3 + latency*0.2 + load*0.2 + utilization*0.3`，低分优先

**伪装引擎**在下游客户端不是真正的 Claude Code 客户端时激活。它改写 TLS 指纹、HTTP 头部、anthropic-beta token、系统提示词、metadata.user_id 和模型 ID，以匹配 Claude Code 流量模式。

详细架构文档请参阅 [docs/architecture.md](docs/architecture.md)。

## 管理仪表盘

管理仪表盘位于 `http://<host>:<port>/admin/`，作为内嵌的单页 HTML 文件提供，无需外部资源。

仪表盘和所有 `/api/*` 端点通过 HTTP Basic Auth 保护（任意用户名 + 配置的管理密码）。

可用 API 端点：

| 端点 | 说明 |
|------|------|
| `GET /admin/` | 仪表盘 HTML |
| `GET /api/accounts` | 账户列表（含健康状态和负载） |
| `POST /api/accounts/add` | 添加新账户 |
| `POST /api/accounts/remove` | 删除账户 |
| `POST /api/accounts/proxy` | 更新账户代理设置 |
| `GET /api/sessions` | 活跃会话列表 |
| `POST /api/oauth/login/start` | 启动 OAuth PKCE 登录流程 |
| `POST /api/oauth/login/complete` | 用授权码完成 OAuth 登录 |
| `POST /api/oauth/refresh` | 强制刷新账户令牌 |
| `POST /api/oauth/logout` | 撤销并删除账户令牌 |
