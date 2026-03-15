# Test Coverage Improvement Design

**Date:** 2026-03-15
**Goal:** Bring all packages to 80%+ coverage (整体覆盖率 ≥ 80%)
**Strategy:** Bottom-up (方案 A) — utility packages first, then core, then integration
**Approach:** Pure unit tests with mocks; no external dependencies required

## Current State

| Package | Coverage | Tests |
|---------|----------|-------|
| auth | 100% | ✅ Complete |
| observe | 100% | ✅ Complete |
| session | 100% | ✅ Complete |
| disguise | 86.9% | ✅ Good |
| proxy | 82.0% | ✅ Good |
| loadbalancer | 80.3% | ✅ Good |
| config | 79.3% | Near target |
| ratelimit | 64.9% | Needs work |
| oauth | 54.3% | Needs work |
| admin | 53.2% | Needs work |
| tls | 3.2% | Critical |
| apierror | 0% | No tests |
| fileutil | 0% | No tests |
| netutil | 0% | No tests |
| server | 0% | No tests |
| cli | 0% | No tests |

## Implementation Tiers

### T1: Zero-Coverage Utility Packages

Simple packages with no tests. Quick wins.

#### 1. `internal/apierror` (0% → ~100%)

Single `Write()` function + two structs. Table-driven tests.

| Test | Validates |
|------|-----------|
| `TestWrite_Success` | Status code, Content-Type header, JSON body structure |
| `TestWrite_ErrorTypes` | Table-driven: overloaded, invalid_request, authentication_error |
| `TestWrite_MarshalFailure` | Broken ResponseWriter → fallback JSON output |

**Mocking:** `httptest.ResponseRecorder` (stdlib)

#### 2. `internal/fileutil` (0% → ~90%)

Single `AtomicWriteFile()` function. Test with temp directories.

| Test | Validates |
|------|-----------|
| `TestAtomicWriteFile_Success` | File content, permissions (0600), no temp files left |
| `TestAtomicWriteFile_Overwrite` | Overwrites existing file atomically |
| `TestAtomicWriteFile_InvalidDir` | Non-existent target directory → error |
| `TestAtomicWriteFile_Permissions` | Table-driven: 0644, 0600, 0400 |

**Mocking:** `t.TempDir()` for isolated filesystem

#### 3. `internal/netutil` (0% → ~80%)

Two functions: `NewSOCKS5Dialer()` and `MaskProxyURL()`.

| Test | Validates |
|------|-----------|
| `TestMaskProxyURL_ValidURL` | Returns host:port, credentials stripped |
| `TestMaskProxyURL_InvalidURL` | Returns "(invalid)" |
| `TestMaskProxyURL_NoAuth` | Works without credentials |
| `TestNewSOCKS5Dialer_ValidURL` | Returns non-nil dialer |
| `TestNewSOCKS5Dialer_WithAuth` | Parses username/password from URL |
| `TestNewSOCKS5Dialer_InvalidURL` | Returns error |

**Mocking:** None for MaskProxyURL; SOCKS5 dialer tests validate return types only

---

### T2: Low-Coverage Core Packages

#### 4. `internal/tls` (3.2% → ~75%)

Mock `net.Conn` and `net.Dialer`; test logic branches, not real TLS handshakes.

| Test | Validates |
|------|-----------|
| `TestWithProxyURL_RoundTrip` | Context store/retrieve proxyURL |
| `TestProxyURLFromContext_Missing` | Empty context returns empty string |
| `TestGetOrCreateTransport_Caching` | Same proxyURL → same transport instance |
| `TestGetOrCreateTransport_DifferentProxy` | Different proxyURL → different instance |
| `TestRoundTrip_HTTPS` | HTTPS requests go through pooled transport |
| `TestRoundTrip_HTTP` | HTTP requests bypass TLS fingerprinting |
| `TestDialTCP_Direct` | No proxy → direct dial |
| `TestDialTCP_WithSOCKS5` | Proxy URL in context → SOCKS5 dialer used |

**Mocking:** Custom `net.Conn` stub, `httptest.NewServer` for HTTP tests

#### 5. `internal/ratelimit` (64.9% → ~85%)

Missing: `cleanup()` logic and `StartCleanup()` goroutine.

| Test | Validates |
|------|-----------|
| `TestCleanup_RemovesExpiredVisitors` | Expired visitors removed from map |
| `TestCleanup_KeepsActiveVisitors` | Active visitors retained |
| `TestStartCleanup_ContextCancel` | Goroutine exits on context cancel |
| `TestAllow_ConcurrentAccess` | Multiple goroutines don't panic or corrupt state |

**Mocking:** None needed; use short window durations for timing tests

#### 6. `internal/oauth` (54.3% → ~80%)

Mock Anthropic token endpoint with `httptest.NewServer`.

| Test | Validates |
|------|-----------|
| **provider.go** | |
| `TestAuthorizationURL` | URL contains state, challenge, scopes |
| `TestExchangeCode_Success` | Mock server returns token, parsed correctly |
| `TestExchangeCode_Error` | Mock server returns error, propagated |
| `TestRefreshToken_Success` | Refresh flow succeeds |
| `TestRefreshToken_Error` | Refresh failure propagated |
| `TestGetProxyClient_Caching` | Same proxyURL returns cached client |
| **manager.go** | |
| `TestUpdateAccounts_AddNew` | New account creates mutex |
| `TestUpdateAccounts_RemoveOld` | Removed account cleaned up |
| `TestExchangeAndSave` | Code exchange + token persist |
| `TestForceRefresh` | Force refresh path |
| `TestMarkTokenExpired` | Expired flag triggers refresh on next get |
| `TestGetValidToken_Concurrent` | Multiple goroutines don't duplicate refresh |

**Mocking:** `httptest.NewServer` for token endpoint; `t.TempDir()` for token store

#### 7. `internal/admin` (53.2% → ~80%)

`httptest.ResponseRecorder` for each handler endpoint.

| Test | Validates |
|------|-----------|
| `TestHandleOAuthLoginComplete_Success` | 200 + account bound |
| `TestHandleOAuthLoginComplete_InvalidSession` | 404/400 response |
| `TestHandleOAuthRefresh_Success` | Force refresh + 200 |
| `TestHandleOAuthLogout_Success` | Logout + token cleared |
| `TestHandleAddAccount_Success` | Account created + callback |
| `TestHandleAddAccount_Duplicate` | 409 conflict |
| `TestHandleRemoveAccount_Success` | Account deleted |
| `TestHandleRemoveAccount_NotFound` | 404 response |
| `TestHandleUpdateProxy` | Proxy URL updated |
| `TestHandleSessions` | Returns active session list |
| `TestHandleDashboard` | Returns HTML + 200 |
| `TestWriteJSON_WriteError` | Helper functions format correctly |

**Mocking:** Mock `OAuthManager` interface, mock `AccountRegistry`, mock `SessionStore`

---

### T3: Integration Entry Points

#### 8. `internal/config` (79.3% → ~85%)

Small gap; only edge cases needed.

| Test | Validates |
|------|-----------|
| `TestRuntimeAccount_AllFields` | All fields mapped correctly |
| `TestRuntimeAccounts_MultipleAccounts` | Batch conversion |
| `TestRegistryEnable_Disable` | Enable/Disable persists + triggers callback |
| `TestRegistrySetProxy` | Proxy URL persisted |
| `TestValidate_EdgeCases` | Port 0, negative concurrency, empty base_url |

#### 9. `internal/server` (0% → ~80%)

Glue layer — test wiring correctness, not business logic.

| Test | Validates |
|------|-----------|
| `TestNew_InitializesSubsystems` | All subsystems non-nil |
| `TestNew_RoutesRegistered` | Key routes exist (/v1/messages, /admin/, /health) |
| `TestRecoveryMiddleware` | Panic recovery → 500 response |
| `TestRequestLogMiddleware` | Logs key fields |
| `TestBasicAuth` | Correct/wrong password auth |
| `TestLoggingResponseWriter` | WriteHeader captures status |
| `TestShutdown_PersistsState` | Shutdown saves usage data |

**Mocking:** Stub all internal subsystems; test middleware in isolation

#### 10. `internal/cli` (0% → ~60%)

CLI entry layer — low ROI, cover testable parts only.

| Test | Validates |
|------|-----------|
| `TestVersionCmd` | Output contains version string |
| `TestExecute_NoArgs` | Default startup behavior (mock server) |
| `TestRootCmd_ConfigFlag` | --config flag parsing |

---

## Target Coverage Summary

| Package | Current | Target |
|---------|---------|--------|
| apierror | 0% | ~100% |
| fileutil | 0% | ~90% |
| netutil | 0% | ~80% |
| tls | 3.2% | ~75% |
| ratelimit | 64.9% | ~85% |
| oauth | 54.3% | ~80% |
| admin | 53.2% | ~80% |
| config | 79.3% | ~85% |
| server | 0% | ~80% |
| cli | 0% | ~60% |

## Constraints

- **Pure unit tests only** — no real network connections, no external services
- **Mock all external dependencies** — use `httptest`, `t.TempDir()`, interface stubs
- **Follow existing patterns** — table-driven tests, `t.Parallel()`, `_test.go` in same package
- **`-race` flag required** — all tests must pass with race detector
- **No new dependencies** — use stdlib `testing`, `httptest`, `io` mocks only

## Implementation Order

1. T1: apierror → fileutil → netutil (3 packages, ~1 session)
2. T2: tls → ratelimit → oauth → admin (4 packages, ~2-3 sessions)
3. T3: config → server → cli (3 packages, ~1-2 sessions)

Total: ~60 test cases across 10 packages.
