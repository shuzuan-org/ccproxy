# Test Coverage Improvement Design

**Date:** 2026-03-15
**Goal:** Bring most packages to 80%+ coverage; tls (~45%) and server (~50%) limited by architecture
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
| `TestWrite_WriterError` | Broken ResponseWriter → no panic (error silently ignored) |

**Note:** The `json.Marshal` fallback branch (line 27-31) is dead code — the `Response` struct
contains only string fields and always marshals successfully. This branch is excluded from
coverage targets.

**Mocking:** `httptest.ResponseRecorder` (stdlib); broken writer stub for error path

#### 2. `internal/fileutil` (0% → ~90%)

Single `AtomicWriteFile()` function. Test with temp directories.

| Test | Validates |
|------|-----------|
| `TestAtomicWriteFile_Success` | File content, permissions (0600), no temp files left |
| `TestAtomicWriteFile_Overwrite` | Overwrites existing file atomically |
| `TestAtomicWriteFile_InvalidDir` | Non-existent target directory → error |
| `TestAtomicWriteFile_Permissions` | Table-driven: 0644, 0600, 0400 |
| `TestAtomicWriteFile_NoTempFileOnError` | Verify temp file cleaned up on write/chmod/sync failure |

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

#### 4. `internal/tls` (3.2% → ~45%)

Test pure functions, context helpers, and transport caching logic. The TLS handshake path
(`utls.UClient.Handshake()`) requires a real TCP peer and cannot be covered by pure unit tests —
this is excluded from coverage targets.

| Test | Validates |
|------|-----------|
| `TestWithProxyURL_RoundTrip` | Context store/retrieve proxyURL |
| `TestProxyURLFromContext_Missing` | Empty context returns empty string |
| `TestGetOrCreateTransport_Caching` | Same proxyURL → same transport instance |
| `TestGetOrCreateTransport_DifferentProxy` | Different proxyURL → different instance |
| `TestRoundTrip_NonHTTPS` | Non-HTTPS requests bypass TLS fingerprinting |

**Limitation:** `RoundTrip` (HTTPS path), `makeDialTLSContext`, and `dialTCP` success paths
require real network I/O and `utls` handshake — not coverable under "pure unit tests" constraint.
Error paths (connection refused, dial timeout) can be partially tested.

**Mocking:** Context manipulation only; no network mocks needed for achievable tests

#### 5. `internal/ratelimit` (64.9% → ~85%)

Missing: `cleanup()` logic and `StartCleanup()` goroutine.

| Test | Validates |
|------|-----------|
| `TestCleanup_RemovesExpiredVisitors` | Expired visitors removed from map |
| `TestCleanup_KeepsActiveVisitors` | Active visitors retained |
| `TestStartCleanup_ContextCancel` | Goroutine exits on context cancel |
| `TestAllow_ConcurrentAccess` | Multiple goroutines don't panic or corrupt state |

**Approach:** White-box tests in same package. Call `cleanup()` directly with manually
manipulated `visitor.resetAt` timestamps — avoid goroutine timing dependencies that cause
flaky tests under `-race`. Only `TestStartCleanup_ContextCancel` uses goroutines (brief).

**Mocking:** None needed

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
| `TestUpdateAccounts_RemoveOld` | Removed account's mutex NOT cleaned (known limitation — document as memory leak note) |
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
| `TestHandleOAuthLoginComplete_StateMismatch` | CSRF state validation → 400 (security-critical) |
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

**Note:** `Handler` holds concrete type pointers (`*oauth.Manager`, `*config.AccountRegistry`,
etc.), not interfaces. Tests must construct real objects with `t.TempDir()` for filesystem
isolation, following the pattern already established in existing `handler_test.go`.

Some tests listed above may already exist in `handler_test.go` — verify before implementing
and only add truly missing cases (e.g., `TestHandleUpdateProxy`, `TestHandleOAuthLoginComplete`
full flow, `TestHandleOAuthLoginComplete_StateMismatch` for CSRF validation).

**Mocking:** Real objects with `t.TempDir()` isolation (no interfaces available)

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

#### 9. `internal/server` (0% → ~50%)

Glue layer. `New()` uses concrete types (not interfaces) and creates real filesystem state,
so it cannot be purely mocked. Focus on **middleware functions** which are independently testable.

| Test | Validates |
|------|-----------|
| `TestRecoveryMiddleware` | Panic recovery → 500 response |
| `TestRequestLogMiddleware` | Logs key fields |
| `TestBasicAuth` | Correct/wrong password auth |
| `TestLoggingResponseWriter` | WriteHeader captures status |
| `TestNew_WithTempDir` | Full init with `t.TempDir()` — verifies subsystems non-nil (semi-integration) |
| `TestShutdown_PersistsState` | Shutdown saves usage data (requires init first) |

**Limitation:** `New()` depends on concrete types (`config.NewAccountRegistry`, `oauth.NewTokenStore`,
etc.) that perform real file I/O. Tests use `t.TempDir()` for isolation rather than pure mocks.
80% target is unrealistic — middleware tests alone cover ~50% of statements.

**Mocking:** `t.TempDir()` for filesystem isolation; `httptest.ResponseRecorder` for middleware

#### 10. `internal/cli` (0% → ~60%)

CLI entry layer — low ROI, cover testable parts only.

| Test | Validates |
|------|-----------|
| `TestVersionCmd` | Output contains version string |
| `TestExecute_NoArgs` | Default startup behavior (mock server) |
| `TestRootCmd_ConfigFlag` | --config flag parsing |

---

## Target Coverage Summary

| Package | Current | Target | Notes |
|---------|---------|--------|-------|
| apierror | 0% | ~90% | Marshal fallback is dead code |
| fileutil | 0% | ~90% | |
| netutil | 0% | ~80% | |
| tls | 3.2% | ~45% | TLS handshake path excluded (needs real network) |
| ratelimit | 64.9% | ~85% | |
| oauth | 54.3% | ~80% | |
| admin | 53.2% | ~80% | Some tests may already exist — verify first |
| config | 79.3% | ~85% | |
| server | 0% | ~50% | Concrete deps limit pure unit test coverage |
| cli | 0% | ~60% | |

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

## Known Limitations

- `tls`: TLS handshake path requires real network I/O; pure unit test ceiling is ~45%
- `server`: `New()` uses concrete types without interfaces; cannot be fully mocked
- `apierror`: `json.Marshal` fallback branch is dead code (struct has only string fields)
- `oauth`: `UpdateAccounts()` does not clean up mutexes for removed accounts (memory leak)
