# ccproxy TLS 指纹对齐 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将 ccproxy 默认 HTTPS 出站 TLS 指纹从旧版 Node.js 20/OpenSSL 3 风格升级为与 sub2api 当前默认 Node.js 24 风格实现一致。

**Architecture:** 保持 `internal/proxy/handler.go` 对 `proxytls.NewTransport()` 的调用方式不变，只重构 `internal/tls/fingerprint.go` 内部的默认 `ClientHelloSpec` 构造逻辑。实现上借鉴 `sub2api/backend/internal/pkg/tlsfingerprint/dialer.go` 的默认 builder，将新版默认参数集中到 `internal/tls` 内部，并用测试锁定新的 JA3、扩展顺序与关键默认字段。

**Tech Stack:** Go 1.25, net/http, utls, go test

---

## File Structure

- Modify: `internal/tls/fingerprint.go`
  - 保留 transport 缓存、SOCKS5 拨号和 `NewTransport()` 公开接口。
  - 删除旧 Node.js 20 时代的大型固定 spec 常量与实现。
  - 引入与 sub2api 默认 Node.js 24 指纹对齐的默认参数和 builder。
- Modify: `internal/tls/fingerprint_test.go`
  - 将旧 JA3、cipher suite 数量、扩展类型假设更新为新版默认值。
  - 新增对 ALPN、supported versions、key share、ECH、GREASE 行为的测试。
- Reference only: `internal/proxy/handler.go`
  - 确认不需要改动，继续使用 `proxytls.NewTransport()`。

### Task 1: 锁定新版默认 TLS 指纹测试

**Files:**
- Modify: `internal/tls/fingerprint_test.go`
- Test: `internal/tls/fingerprint_test.go`

- [ ] **Step 1: 写失败测试，更新 cipher suite 数量与 JA3 期望值**

```go
func TestClaudeCLIv2Spec_CipherSuiteCount(t *testing.T) {
	spec := claudeCLIv2Spec()
	if got := len(spec.CipherSuites); got != 17 {
		t.Errorf("expected 17 cipher suites, got %d", got)
	}
}

func TestClaudeCLIv2Spec_JA3Hash(t *testing.T) {
	t.Parallel()
	const expectedJA3 = "44f88fca027f27bab4bb08d4af15f23e"

	spec := claudeCLIv2Spec()
	got := ja3Hash(spec)
	if got != expectedJA3 {
		t.Errorf("JA3 hash mismatch:\n  got:  %s\n  want: %s", got, expectedJA3)
	}
}
```

- [ ] **Step 2: 为新版默认字段添加失败测试**

```go
func TestClaudeCLIv2Spec_DefaultALPN(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			if len(alpn.AlpnProtocols) != 1 || alpn.AlpnProtocols[0] != "http/1.1" {
				t.Fatalf("unexpected ALPN protocols: %#v", alpn.AlpnProtocols)
			}
			return
		}
	}
	t.Fatal("expected ALPNExtension")
}

func TestClaudeCLIv2Spec_DefaultSupportedVersions(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if versions, ok := ext.(*utls.SupportedVersionsExtension); ok {
			want := []uint16{utls.VersionTLS13, utls.VersionTLS12}
			if len(versions.Versions) != len(want) {
				t.Fatalf("supported versions len=%d want=%d", len(versions.Versions), len(want))
			}
			for i := range want {
				if versions.Versions[i] != want[i] {
					t.Fatalf("supported version[%d]=0x%04x want 0x%04x", i, versions.Versions[i], want[i])
				}
			}
			return
		}
	}
	t.Fatal("expected SupportedVersionsExtension")
}

func TestClaudeCLIv2Spec_DefaultKeyShare(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			if len(ks.KeyShares) != 1 || ks.KeyShares[0].Group != utls.X25519 {
				t.Fatalf("unexpected key shares: %#v", ks.KeyShares)
			}
			return
		}
	}
	t.Fatal("expected KeyShareExtension")
}
```

- [ ] **Step 3: 为 ECH 扩展与默认无 GREASE 添加失败测试**

```go
func TestClaudeCLIv2Spec_DefaultIncludesECH(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.GREASEEncryptedClientHelloExtension); ok {
			return
		}
	}
	t.Fatal("expected GREASEEncryptedClientHelloExtension")
}

func TestClaudeCLIv2Spec_DefaultHasNoGREASEBookends(t *testing.T) {
	spec := claudeCLIv2Spec()
	for _, ext := range spec.Extensions {
		if _, ok := ext.(*utls.UtlsGREASEExtension); ok {
			t.Fatal("did not expect UtlsGREASEExtension in default spec")
		}
	}
}
```

- [ ] **Step 4: 运行 TLS 测试并确认失败**

Run: `go test ./internal/tls -run 'TestClaudeCLIv2Spec|TestNewTransport|TestRoundTrip_NonHTTPS' -v`

Expected: 旧实现下至少出现以下失败之一：
- `expected 17 cipher suites, got 59`
- JA3 hash mismatch，当前值仍为 `1a28e69016765d92e3b381168d68922c`
- 默认扩展字段断言失败

- [ ] **Step 5: 提交测试基线**

```bash
git add internal/tls/fingerprint_test.go
git commit -m "test(tls): lock node24 fingerprint expectations"
```

### Task 2: 用新版默认 builder 替换旧 TLS spec

**Files:**
- Modify: `internal/tls/fingerprint.go`
- Test: `internal/tls/fingerprint_test.go`

- [ ] **Step 1: 删除旧 Node.js 20 大型 spec 常量，新增新版默认参数定义**

在 `internal/tls/fingerprint.go` 中删除旧的 59-cipher 常量块和 ffdhe 常量，改为加入与 `sub2api` 默认实现一致的最小参数集：

```go
var (
	defaultCipherSuites = []uint16{
		0x1301, // TLS_AES_128_GCM_SHA256
		0x1302, // TLS_AES_256_GCM_SHA384
		0x1303, // TLS_CHACHA20_POLY1305_SHA256
		0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
		0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
		0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		0xcca9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
		0xcca8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
		0xc009, // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
		0xc013, // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
		0xc00a, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
		0xc014, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
		0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
		0x009d, // TLS_RSA_WITH_AES_256_GCM_SHA384
		0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
		0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
	}

	defaultCurves = []utls.CurveID{utls.X25519, utls.CurveP256, utls.CurveP384}
	defaultPointFormats = []uint16{0}
	defaultSignatureAlgorithms = []utls.SignatureScheme{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
	}
	defaultExtensionOrder = []uint16{0, 65037, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43}
)
```

- [ ] **Step 2: 增加 builder 辅助函数，按默认参数组装 `ClientHelloSpec`**

在 `internal/tls/fingerprint.go` 中加入这些辅助函数，并让实现与 `sub2api` 默认 builder 保持一致：

```go
func toUint8s(vals []uint16) []uint8 {
	out := make([]uint8, len(vals))
	for i, v := range vals {
		out[i] = uint8(v)
	}
	return out
}

func buildDefaultExtensions() []utls.TLSExtension {
	keyShares := []utls.KeyShare{{Group: utls.X25519}}
	return []utls.TLSExtension{
		&utls.SNIExtension{},
		&utls.GREASEEncryptedClientHelloExtension{},
		&utls.ExtendedMasterSecretExtension{},
		&utls.RenegotiationInfoExtension{},
		&utls.SupportedCurvesExtension{Curves: defaultCurves},
		&utls.SupportedPointsExtension{SupportedPoints: toUint8s(defaultPointFormats)},
		&utls.SessionTicketExtension{},
		&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
		&utls.StatusRequestExtension{},
		&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: defaultSignatureAlgorithms},
		&utls.SCTExtension{},
		&utls.KeyShareExtension{KeyShares: keyShares},
		&utls.PSKKeyExchangeModesExtension{Modes: []uint8{uint8(utls.PskModeDHE)}},
		&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
	}
}
```

- [ ] **Step 3: 用新 builder 重写 `claudeCLIv2Spec()`**

将 `claudeCLIv2Spec()` 改成：

```go
func claudeCLIv2Spec() *utls.ClientHelloSpec {
	return &utls.ClientHelloSpec{
		CipherSuites:       append([]uint16(nil), defaultCipherSuites...),
		CompressionMethods: []uint8{0},
		Extensions:         buildDefaultExtensions(),
		TLSVersMax:         utls.VersionTLS13,
		TLSVersMin:         utls.VersionTLS10,
	}
}
```

保留 `makeDialTLSContext()` 中“每次连接 fresh 构造 spec”的逻辑，不修改 `NewTransport()`、`fingerprintTransport`、`dialTCP()`。

- [ ] **Step 4: 运行 TLS 单测并确认通过**

Run: `go test ./internal/tls -v`

Expected: PASS，且包含：
- `TestClaudeCLIv2Spec_CipherSuiteCount`
- `TestClaudeCLIv2Spec_JA3Hash`
- `TestClaudeCLIv2Spec_DefaultALPN`
- `TestClaudeCLIv2Spec_DefaultIncludesECH`

- [ ] **Step 5: 提交 builder 重构**

```bash
git add internal/tls/fingerprint.go internal/tls/fingerprint_test.go
git commit -m "feat(tls): align default fingerprint with sub2api"
```

### Task 3: 验证接线未变且全包测试通过

**Files:**
- Reference: `internal/proxy/handler.go:54-66`
- Test: `internal/tls/fingerprint_test.go`

- [ ] **Step 1: 确认 `internal/proxy/handler.go` 无需修改**

检查现有接线仍为：

```go
func NewHandler(
	baseURL string,
	requestTimeout int,
	balancer *loadbalancer.Balancer,
	disguiseEngine *disguise.Engine,
	oauthManager *oauth.Manager,
) *Handler {
	timeout := time.Duration(requestTimeout) * time.Second
	if timeout == 0 {
		timeout = 600 * time.Second
	}
	transport := proxytls.NewTransport()

	return &Handler{
		balancer:     balancer,
		disguise:     disguiseEngine,
		oauthManager: oauthManager,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   timeout,
		},
		baseURL: baseURL,
	}
}
```

Expected: 不做改动，证明本次升级只在 `internal/tls` 内部生效。

- [ ] **Step 2: 运行聚焦回归测试**

Run: `go test ./internal/tls ./internal/proxy -run 'TestClaudeCLIv2Spec|TestNewTransport|TestRoundTrip_NonHTTPS|TestNewHandler' -v`

Expected: PASS，确认 TLS 升级未破坏 `proxy` 层 transport 接线。

- [ ] **Step 3: 运行完整相关测试集**

Run: `go test ./internal/tls ./internal/proxy ./internal/disguise -race -v`

Expected: PASS，无新的 race 或回归失败。

- [ ] **Step 4: 记录验证结果并自查 diff**

Run: `git diff -- internal/tls/fingerprint.go internal/tls/fingerprint_test.go`

Expected: 只包含默认 TLS spec 升级与对应测试更新，不出现 `internal/proxy/handler.go`、`internal/disguise/*` 的无关改动。

- [ ] **Step 5: 提交最终实现**

```bash
git add internal/tls/fingerprint.go internal/tls/fingerprint_test.go
git commit -m "test(tls): cover node24 default fingerprint fields"
```

## Self-Review

- **Spec coverage:**
  - 默认 TLS 指纹升级：Task 2
  - 保持 transport 接线不变：Task 3 Step 1
  - 测试锁定 JA3、扩展顺序、关键默认字段：Task 1 + Task 2 + Task 3
  - 不引入 profile 管理面：所有任务仅修改 `internal/tls/*`
- **Placeholder scan:** 无 TBD/TODO/“自行实现”描述；所有代码步骤都给出具体代码块与命令。
- **Type consistency:** 全文统一使用 `claudeCLIv2Spec()`、`defaultCipherSuites`、`buildDefaultExtensions()`、`NewTransport()` 等命名，没有前后漂移。

