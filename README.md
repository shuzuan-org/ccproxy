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

部署方式选择：
- CLI 一键部署适合大多数 VPS / 个人自托管用户。
- Docker 适合已有容器环境或临时体验。
- 源码构建适合开发调试。

### 推荐：CLI 一键部署（Linux）

这是默认推荐路径：单二进制配合安装脚本即可完成部署，适合长期运行的宿主机场景。
可按需接入 systemd、Caddy HTTPS，后续也便于使用内置升级能力维护。

完整 HTTPS 部署（自动安装 Caddy + 配置 Let's Encrypt 证书）：

```bash
curl -fsSL https://raw.githubusercontent.com/shuzuan-org/ccproxy/master/install.sh | \
  sudo sh -s -- --domain proxy.example.com
```

仅安装 ccproxy + systemd 服务（用户自行配置 HTTPS）：

```bash
curl -fsSL https://raw.githubusercontent.com/shuzuan-org/ccproxy/master/install.sh | \
  sudo sh -s -- --with-systemd
```

仅安装二进制：

```bash
curl -fsSL https://raw.githubusercontent.com/shuzuan-org/ccproxy/master/install.sh | sh
```

### Docker（可选）

适合已有 Docker 环境、容器化维护或快速试用；如果是在宿主机长期部署，优先使用上面的 CLI 方式。

一行命令启动：

```bash
docker run -d --name ccproxy --hostname ccproxy \
  -p 80:80 -v ccproxy-data:/data \
  saloolooo/ccproxy
```

启用 HTTPS 自动证书（需要域名已解析到服务器）：

```bash
docker run -d --name ccproxy --hostname ccproxy \
  -p 80:80 -p 443:443 -v ccproxy-data:/data \
  -e DOMAIN=proxy.example.com \
  saloolooo/ccproxy
```

> **注意：** `--hostname ccproxy` 是必需的——OAuth 令牌加密密钥从主机名派生，缺少固定主机名会导致容器重建后令牌失效。

容器内置 Caddy 反向代理，自动处理 TLS 证书。配置文件和数据持久化在 `/data` 卷中。

### 从源码构建

```bash
make build
# 输出：bin/ccproxy
```

```bash
./bin/ccproxy
```

首次启动时，ccproxy 会自动生成 `config.toml`（如缺失）、API 密钥和管理密码，并打印到控制台。

**添加账户：** 打开 `http://<host>:<port>/admin/`，使用"Add Claude"按钮。在仪表盘中通过 OAuth 登录流程认证每个账户。

代理默认监听 `http://127.0.0.1:3000`。如需对外暴露，将 `config.toml` 中的 `host` 改为 `"0.0.0.0"`（推荐通过反向代理如 Caddy/Nginx 转发）。将你的 Claude 兼容客户端指向此地址，使用生成的 API 密钥作为 Bearer token。

## 配置参考

配置从 `config.toml` 读取（使用 `-c <path>` 覆盖）。修改后需要重启才能生效。

### `[server]`

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `host` | `127.0.0.1` | 监听地址 |
| `port` | `3000` | 监听端口 |
| `admin_password` | （自动生成） | `/admin/` 和 `/api/*` 路由的 Basic Auth 密码 |
| `rate_limit` | `60` | 管理路由每 IP 每分钟最大请求数 |
| `base_url` | `https://api.anthropic.com` | 上游 Anthropic API 基础 URL |
| `request_timeout` | `600` | 上游请求超时（秒），对齐 Claude Code 的 X-Stainless-Timeout |
| `max_concurrency` | `5` | 每账户并发硬上限（实际值由预算利用率动态调整） |
| `log_level` | `info` | 日志级别（`debug`、`info`、`warn`、`error`） |
| `auto_update` | `true` | 启用后台自动检查更新 |
| `update_check_interval` | `1h` | 检查间隔（5m - 24h） |
| `update_channel` | `stable` | 更新渠道：`stable` 仅接收正式版，`beta` 也接收预发布版 |
| `update_repo` | `shuzuan-org/ccproxy` | GitHub 仓库（用于自动更新） |

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
host = "127.0.0.1"
port = 3000
base_url = "https://api.anthropic.com"
request_timeout = 600
max_concurrency = 5

[[api_keys]]
key = "sk-your-api-key-here"
name = "dev-team"
enabled = true
```

## CLI 用法

```
ccproxy                   启动代理服务器（前台运行）
ccproxy version           打印版本号
ccproxy upgrade           检查并应用更新
ccproxy upgrade --check   仅检查，不应用
ccproxy upgrade --force   强制重新安装当前版本
ccproxy -c <path>         使用指定配置文件（默认：config.toml）
```

## 架构概览

```
ccproxy（单二进制）
├── CLI 层 (cobra)
│   └── start（根命令）、version、upgrade
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
    ├── JSON 文件            每账户指纹 (data/fingerprints.json)
    ├── JSON 文件            持久化健康状态 (data/health_state.json)
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
| `GET /api/update/status` | 更新状态（当前版本、最新版本） |
| `POST /api/update/check` | 立即检查更新 |
| `POST /api/update/apply` | 应用更新并重启 |
