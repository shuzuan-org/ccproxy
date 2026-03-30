# ccproxy TLS 指纹对齐设计

日期：2026-03-30

## 背景

当前 `ccproxy` 的默认出站 TLS 指纹实现位于 `internal/tls/fingerprint.go`，锁定的是较旧的 Claude CLI / Node.js 20.x 风格握手参数：

- 59 个 cipher suites
- 旧版默认扩展组合
- JA3：`1a28e69016765d92e3b381168d68922c`

而 `sub2api` 最新默认 TLS 指纹实现位于 `sub2api/backend/internal/pkg/tlsfingerprint/dialer.go`，已经切换到较新的 Node.js 24 风格默认配置：

- 17 个 cipher suites
- 默认扩展顺序包含 ECH(65037)
- 默认不启用 GREASE
- JA3：`44f88fca027f27bab4bb08d4af15f23e`

本次目标是仅将 **TLS 指纹默认实现** 从 `sub2api` 迁移到 `ccproxy`，不扩展到其他伪装层能力。

## 目标

将 `sub2api` 最新默认 Claude TLS 指纹实现迁移到 `ccproxy`，并满足：

- 仅对齐默认 TLS fingerprint
- 最小侵入接入 `ccproxy` 现有出站链路
- 不引入 TLS fingerprint profile 管理能力
- 不改变 `ccproxy` 现有上层代理、伪装、OAuth、负载均衡语义

结果应为：`ccproxy` 的 HTTPS 出站握手从旧的 Node.js 20/OpenSSL 3 风格升级为 `sub2api` 当前默认的 Node.js 24 风格 TLS 指纹。

## 范围

### 包含

- 升级 `internal/tls` 中默认 `ClientHelloSpec`
- 保持 `NewTransport()` 接线方式不变
- 更新 TLS 单元测试以锁定新的默认指纹行为

### 不包含

- `internal/disguise` 的 header / beta / metadata / model / thinking 逻辑
- header wire casing 迁移
- response header filter 迁移
- TLS fingerprint profile 的配置、存储、管理接口
- 多 profile 切换能力
- 失败后自动 fallback 到旧 TLS 指纹

## 现状与差异

### ccproxy 当前实现

文件：`internal/tls/fingerprint.go`

特点：

- `NewTransport()` 返回自定义 `http.RoundTripper`
- 以 `proxyURL` 为 key 复用 `*http.Transport`
- HTTPS 请求在 `DialTLSContext` 中使用 `utls.HelloCustom`
- 通过 `claudeCLIv2Spec()` 直接构造完整固定 spec
- 当前 spec 注释和测试锁定为 Node.js 20.x + OpenSSL 3.x

### sub2api 最新实现

文件：`sub2api/backend/internal/pkg/tlsfingerprint/dialer.go`

特点：

- 默认参数不再是巨大手写 spec，而是由默认 profile 组装
- 默认 cipher suites 为 17 个
- 默认扩展顺序为 Node.js 24 风格
- 显式包含 ECH(65037)
- 默认 `EnableGREASE = false`
- 默认 JA3 锁定为 `44f88fca027f27bab4bb08d4af15f23e`

### 本次迁移的本质

本次不是“小修参数”，而是将 `ccproxy` 的默认 TLS 指纹从旧版 Node.js 20 风格升级为 `sub2api` 当前默认的 Node.js 24 风格实现。

## 设计

### 1. 保持 transport 架构不变

保留 `ccproxy` 当前 TLS transport 的整体结构：

- `NewTransport()`
- `fingerprintTransport`
- `getOrCreateTransport(proxyURL string)`
- direct / SOCKS5 拨号路径
- 每次握手 fresh 构建 spec

上层 `proxy`、`oauth`、`loadbalancer`、`disguise` 不感知 TLS 实现细节变化。

### 2. 将固定旧 spec 改为新版默认 profile builder

当前 `claudeCLIv2Spec()` 直接返回旧的固定 Node.js 20 spec。迁移后应改为基于一组“新版默认参数”构造 `utls.ClientHelloSpec`。

建议保留函数入口，但内部实现从“硬编码巨大 spec”切换为“默认 profile 构建器”。

目标默认行为与 `sub2api/backend/internal/pkg/tlsfingerprint/dialer.go` 对齐，包括：

- cipher suites
- curves / supported groups
- point formats
- signature algorithms
- ALPN protocols
- supported versions
- key share groups
- PSK modes
- extension order
- ECH 扩展表现形式
- GREASE 默认关闭

### 3. 数据流

迁移后，请求链路保持不变，仅 TLS 握手内容发生变化：

1. 上层创建出站请求
2. 继续走 `internal/tls.NewTransport()`
3. HTTPS 请求进入 `DialTLSContext`
4. 建立 TCP 连接（直连或 SOCKS5）
5. `internal/tls` 构建新的默认 Claude TLS spec
6. 使用 uTLS 发起握手
7. 握手成功后按原有 HTTP 流程继续发送请求

本次不改变账号选择、请求体伪装、header 伪装、SSE 转发等行为。

### 4. 错误处理

保持当前错误处理策略，不新增自动降级：

- TCP dial 失败：直接返回错误
- `ApplyPreset` 失败：关闭连接并返回错误
- TLS handshake 失败：关闭连接并返回错误

不在本次设计中加入：

- 标准库 TLS fallback
- 旧指纹 fallback
- 按错误类型切换不同 profile

这样能保证默认指纹行为确定且可测试。

## 实现边界

### 主要修改文件

- `internal/tls/fingerprint.go`
- `internal/tls/fingerprint_test.go`

### 参考实现来源

- `sub2api/backend/internal/pkg/tlsfingerprint/dialer.go`
- `sub2api/backend/internal/pkg/tlsfingerprint/dialer_test.go`
- `sub2api/backend/internal/pkg/tlsfingerprint/dialer_capture_test.go`

### 明确不迁移的部分

- `Profile` 的外部管理能力
- ent schema / repository / admin handler 中与 TLS profile 相关的管理面
- HTTP proxy 独立 dialer 类型体系（除非实现细节复用需要局部借鉴）

## 测试策略

### 保留的测试

- `NewTransport()` 返回值类型测试
- transport 按 `proxyURL` 缓存复用测试
- 非 HTTPS 请求 fallback 到标准 transport 的测试
- spec 每次调用 fresh 构建的测试

### 需要更新的测试断言

- cipher suite count：从 59 更新为 17
- JA3 hash：从 `1a28e69016765d92e3b381168d68922c` 更新为 `44f88fca027f27bab4bb08d4af15f23e`
- 默认扩展顺序：与 `sub2api` 默认 builder 保持一致

### 建议新增的测试

- 默认 ALPN 为 `http/1.1`
- 默认 supported versions 为 TLS 1.3 + TLS 1.2
- 默认 key share groups 为 X25519
- 默认 spec 中包含 ECH 对应扩展
- 默认不启用 GREASE

如后续需要更高置信度，可追加真实 TLS 指纹捕获型集成测试，但不作为本次设计必做项。

## 风险与应对

### 风险 1：只迁移部分参数，导致表面升级但真实握手仍不一致

**应对：** 以 `sub2api` 当前默认 builder 为基准整体迁移，不做“只挑几个参数改”的折中版本。

### 风险 2：连接池复用掩盖 spec 是否真正生效

**应对：** 保持每次新连接 fresh 构造 spec，并保留相应测试。

### 风险 3：个别网络环境对新版扩展组合兼容性较差

**应对：** 本次先不引入 fallback，保持行为单一；若后续观测到兼容性问题，再单独设计回退策略。

## 完成定义

当以下条件同时满足，本次设计目标即视为完成：

- `ccproxy/internal/tls` 默认 spec 与 `sub2api` 当前默认 Node.js 24 TLS profile 对齐
- `ccproxy` 现有 transport 组织方式基本不变
- TLS 单元测试更新为锁定新的 JA3 和默认结构参数
- 不引入 TLS profile 管理能力或额外配置面
