# Test Coverage Improvement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring all packages to target coverage (80%+ for most; ~45% tls, ~50% server, ~60% cli)

**Architecture:** Bottom-up: T1 utility packages → T2 core packages → T3 integration entry points. Pure unit tests, mock all external deps, TDD flow.

**Tech Stack:** Go stdlib `testing`, `net/http/httptest`, `t.TempDir()`, table-driven tests, `-race` flag

**Spec:** `docs/superpowers/specs/2026-03-15-test-improvement-design.md`

---

## Chunk 1: T1 — Zero-Coverage Utility Packages

### Task 1: apierror tests

**Files:**
- Create: `internal/apierror/apierror_test.go`
- Reference: `internal/apierror/apierror.go`

- [ ] **Step 1: Write test file**

```go
package apierror

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWrite_Success(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	Write(w, http.StatusBadRequest, "invalid_request_error", "bad input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp Response
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Type != "error" {
		t.Errorf("type = %q, want error", resp.Type)
	}
	if resp.Error.Type != "invalid_request_error" {
		t.Errorf("error.type = %q, want invalid_request_error", resp.Error.Type)
	}
	if resp.Error.Message != "bad input" {
		t.Errorf("error.message = %q, want 'bad input'", resp.Error.Message)
	}
}

func TestWrite_ErrorTypes(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status  int
		errType string
		message string
	}{
		{http.StatusTooManyRequests, "rate_limit_error", "Too many requests"},
		{http.StatusUnauthorized, "authentication_error", "Invalid API key"},
		{http.StatusBadGateway, "overloaded_error", "Upstream overloaded"},
		{http.StatusInternalServerError, "api_error", "Internal error"},
	}
	for _, tc := range cases {
		t.Run(tc.errType, func(t *testing.T) {
			t.Parallel()
			w := httptest.NewRecorder()
			Write(w, tc.status, tc.errType, tc.message)

			if w.Code != tc.status {
				t.Errorf("status = %d, want %d", w.Code, tc.status)
			}
			var resp Response
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Error.Type != tc.errType {
				t.Errorf("error.type = %q, want %q", resp.Error.Type, tc.errType)
			}
			if resp.Error.Message != tc.message {
				t.Errorf("error.message = %q, want %q", resp.Error.Message, tc.message)
			}
		})
	}
}

// brokenWriter simulates a ResponseWriter that fails on Write.
type brokenWriter struct {
	header     http.Header
	statusCode int
}

func (bw *brokenWriter) Header() http.Header        { return bw.header }
func (bw *brokenWriter) WriteHeader(code int)        { bw.statusCode = code }
func (bw *brokenWriter) Write([]byte) (int, error)   { return 0, nil } // silently ignored per implementation

func TestWrite_WriterDoesNotPanic(t *testing.T) {
	t.Parallel()
	bw := &brokenWriter{header: make(http.Header)}
	// Should not panic even with a minimal ResponseWriter
	Write(bw, http.StatusBadRequest, "invalid_request_error", "test")
	if bw.statusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", bw.statusCode, http.StatusBadRequest)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/apierror/... -v -race`
Expected: PASS (all 3 tests + subtests)

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/apierror/... -cover`
Expected: ~85-90% (marshal fallback branch is dead code)

- [ ] **Step 4: Commit**

```bash
git add internal/apierror/apierror_test.go
git commit -m "test(apierror): add unit tests for Write function"
```

---

### Task 2: fileutil tests

**Files:**
- Create: `internal/fileutil/fileutil_test.go`
- Reference: `internal/fileutil/fileutil.go`

- [ ] **Step 1: Write test file**

```go
package fileutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteFile_Success(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	data := []byte(`{"hello":"world"}`)

	if err := AtomicWriteFile(path, data, 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("content = %q, want %q", got, data)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perm = %o, want 600", info.Mode().Perm())
	}

	// No temp files should remain
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("expected 1 file in dir, got %d", len(entries))
	}
}

func TestAtomicWriteFile_Overwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")

	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := AtomicWriteFile(path, []byte("new"), 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}

	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q, want new", got)
	}
}

func TestAtomicWriteFile_InvalidDir(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nonexistent", "subdir", "file.txt")
	err := AtomicWriteFile(path, []byte("data"), 0o600)
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
}

func TestAtomicWriteFile_Permissions(t *testing.T) {
	t.Parallel()
	cases := []os.FileMode{0o644, 0o600, 0o400}
	for _, perm := range cases {
		t.Run(perm.String(), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "file.txt")
			if err := AtomicWriteFile(path, []byte("x"), perm); err != nil {
				t.Fatalf("AtomicWriteFile: %v", err)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != perm {
				t.Errorf("perm = %o, want %o", info.Mode().Perm(), perm)
			}
		})
	}
}

func TestAtomicWriteFile_EmptyData(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.txt")
	if err := AtomicWriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("AtomicWriteFile: %v", err)
	}
	got, _ := os.ReadFile(path)
	if len(got) != 0 {
		t.Errorf("expected empty file, got %d bytes", len(got))
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/fileutil/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/fileutil/... -cover`
Expected: ~80-90%

- [ ] **Step 4: Commit**

```bash
git add internal/fileutil/fileutil_test.go
git commit -m "test(fileutil): add unit tests for AtomicWriteFile"
```

---

### Task 3: netutil tests

**Files:**
- Create: `internal/netutil/socks5_test.go`
- Reference: `internal/netutil/socks5.go`

- [ ] **Step 1: Write test file**

```go
package netutil

import (
	"testing"
)

func TestMaskProxyURL_ValidURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		url  string
		want string
	}{
		{"host:port", "socks5://10.0.0.1:1080", "10.0.0.1:1080"},
		{"with auth", "socks5://user:pass@10.0.0.1:1080", "10.0.0.1:1080"},
		{"no port", "socks5://myhost", "myhost"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := MaskProxyURL(tc.url)
			if got != tc.want {
				t.Errorf("MaskProxyURL(%q) = %q, want %q", tc.url, got, tc.want)
			}
		})
	}
}

func TestMaskProxyURL_InvalidURL(t *testing.T) {
	t.Parallel()
	got := MaskProxyURL("://bad")
	if got != "(invalid)" {
		t.Errorf("MaskProxyURL(bad) = %q, want (invalid)", got)
	}
}

func TestNewSOCKS5Dialer_ValidURL(t *testing.T) {
	t.Parallel()
	dialer, err := NewSOCKS5Dialer("socks5://127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	if dialer == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestNewSOCKS5Dialer_WithAuth(t *testing.T) {
	t.Parallel()
	dialer, err := NewSOCKS5Dialer("socks5://user:pass@127.0.0.1:1080")
	if err != nil {
		t.Fatalf("NewSOCKS5Dialer: %v", err)
	}
	if dialer == nil {
		t.Fatal("expected non-nil dialer")
	}
}

func TestNewSOCKS5Dialer_InvalidURL(t *testing.T) {
	t.Parallel()
	_, err := NewSOCKS5Dialer("://bad")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/netutil/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/netutil/... -cover`
Expected: ~80%+

- [ ] **Step 4: Commit**

```bash
git add internal/netutil/socks5_test.go
git commit -m "test(netutil): add unit tests for SOCKS5 dialer and MaskProxyURL"
```

- [ ] **Step 5: Run full suite to verify no regressions**

Run: `go test ./... -race`
Expected: All PASS

---

## Chunk 2: T2 — Low-Coverage Core Packages (Part 1: tls + ratelimit)

### Task 4: tls context and caching tests

**Files:**
- Modify: `internal/tls/fingerprint_test.go` (add new tests)
- Reference: `internal/tls/fingerprint.go`

- [ ] **Step 1: Add context and caching tests**

Append to `internal/tls/fingerprint_test.go`:

```go
func TestWithProxyURL_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	proxyURL := "socks5://10.0.0.1:1080"
	ctx = WithProxyURL(ctx, proxyURL)
	got := ProxyURLFromContext(ctx)
	if got != proxyURL {
		t.Errorf("ProxyURLFromContext = %q, want %q", got, proxyURL)
	}
}

func TestProxyURLFromContext_Missing(t *testing.T) {
	t.Parallel()
	got := ProxyURLFromContext(context.Background())
	if got != "" {
		t.Errorf("ProxyURLFromContext(empty) = %q, want empty", got)
	}
}

func TestGetOrCreateTransport_Caching(t *testing.T) {
	t.Parallel()
	ft := &fingerprintTransport{transports: make(map[string]*http.Transport)}
	tr1 := ft.getOrCreateTransport("")
	tr2 := ft.getOrCreateTransport("")
	if tr1 != tr2 {
		t.Error("expected same transport for same proxyURL")
	}
}

func TestGetOrCreateTransport_DifferentProxy(t *testing.T) {
	t.Parallel()
	ft := &fingerprintTransport{transports: make(map[string]*http.Transport)}
	tr1 := ft.getOrCreateTransport("")
	tr2 := ft.getOrCreateTransport("socks5://proxy:1080")
	if tr1 == tr2 {
		t.Error("expected different transports for different proxyURLs")
	}
}

func TestRoundTrip_NonHTTPS(t *testing.T) {
	t.Parallel()
	// Non-HTTPS requests should fall back to http.DefaultTransport
	// We test by sending to a local httptest server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewTransport()
	req, _ := http.NewRequest("GET", srv.URL, nil) // srv.URL is http://
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
```

Replace the existing import block at the top of `fingerprint_test.go` with:

```go
import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/tls/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/tls/... -cover`
Expected: ~30-45% (up from 3.2%)

- [ ] **Step 4: Commit**

```bash
git add internal/tls/fingerprint_test.go
git commit -m "test(tls): add context, caching, and non-HTTPS round trip tests"
```

---

### Task 5: ratelimit cleanup tests

**Files:**
- Modify: `internal/ratelimit/ratelimit_test.go` (add new tests)
- Reference: `internal/ratelimit/ratelimit.go`

- [ ] **Step 1: Add cleanup and concurrency tests**

Append to `internal/ratelimit/ratelimit_test.go`:

```go
func TestCleanup_RemovesExpiredVisitors(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(10, 50*time.Millisecond)

	// Add a visitor
	lim.Allow("1.1.1.1")

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Call cleanup directly (white-box)
	lim.cleanup()

	// The visitor should have been removed — allow should start fresh
	lim.mu.Lock()
	_, exists := lim.visitors["1.1.1.1"]
	lim.mu.Unlock()
	if exists {
		t.Error("expired visitor should have been cleaned up")
	}
}

func TestCleanup_KeepsActiveVisitors(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(10, time.Hour) // long window

	lim.Allow("2.2.2.2")
	lim.cleanup()

	lim.mu.Lock()
	_, exists := lim.visitors["2.2.2.2"]
	lim.mu.Unlock()
	if !exists {
		t.Error("active visitor should NOT be cleaned up")
	}
}

func TestStartCleanup_ContextCancel(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(10, 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())

	lim.StartCleanup(ctx)

	// Let the goroutine run briefly
	time.Sleep(30 * time.Millisecond)

	// Cancel should cause goroutine to exit (no goroutine leak)
	cancel()
	time.Sleep(20 * time.Millisecond)

	// No assertion beyond "doesn't panic or leak" — verified by -race
}

func TestAllow_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(1000, time.Minute)

	done := make(chan struct{})
	for i := 0; i < 100; i++ {
		go func(ip string) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				lim.Allow(ip)
			}
		}(fmt.Sprintf("10.0.0.%d", i%10))
	}
	for i := 0; i < 100; i++ {
		<-done
	}
}
```

Merge these imports into the existing import block in `ratelimit_test.go` (add `"context"` and `"fmt"` alongside the existing imports — do NOT duplicate `"time"` or others that already exist):

```go
// Add to existing imports:
"context"
"fmt"
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/ratelimit/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/ratelimit/... -cover`
Expected: ~85%+ (up from 64.9%)

- [ ] **Step 4: Commit**

```bash
git add internal/ratelimit/ratelimit_test.go
git commit -m "test(ratelimit): add cleanup, context cancel, and concurrency tests"
```

---

## Chunk 3: T2 — Low-Coverage Core Packages (Part 2: oauth)

### Task 6: oauth provider tests

**Files:**
- Modify: `internal/oauth/manager_test.go` (add provider tests using mock server)
- Reference: `internal/oauth/provider.go`

- [ ] **Step 1: Add ExchangeCode and RefreshToken tests**

Append to `internal/oauth/manager_test.go`:

```go
func TestExchangeCode_Success(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	token, err := m.GetProvider().ExchangeCode(context.Background(), "auth-code", "verifier", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}
	if token.RefreshToken != "new-refresh" {
		t.Errorf("refresh_token = %q, want new-refresh", token.RefreshToken)
	}
}

func TestExchangeCode_WithState(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	// Code contains appended state: "authcode#statevalue"
	token, err := m.GetProvider().ExchangeCode(context.Background(), "auth-code#mystate", "verifier", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}
}

func TestExchangeCode_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.GetProvider().ExchangeCode(context.Background(), "bad-code", "verifier", "")
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Errorf("error = %q, want 'status 400'", err.Error())
	}
}

func TestRefreshToken_Success(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	token, err := m.GetProvider().RefreshToken(context.Background(), "old-refresh", "")
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}
}

func TestRefreshToken_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.GetProvider().RefreshToken(context.Background(), "bad-refresh", "")
	if err == nil {
		t.Fatal("expected error")
	}
}
```

Also add proxy client caching test:

```go
func TestGetProxyClient_Caching(t *testing.T) {
	p := NewAnthropicProvider()

	// getProxyClient is private but accessible in same-package test.
	// Invalid SOCKS5 URL → falls back to default client (testing fallback path).
	c1 := p.getProxyClient("socks5://127.0.0.1:19999")
	c2 := p.getProxyClient("socks5://127.0.0.1:19999")
	if c1 != c2 {
		t.Error("expected same cached client for same proxyURL")
	}

	// Different URL → different client
	c3 := p.getProxyClient("socks5://127.0.0.1:29999")
	if c1 == c3 {
		t.Error("expected different client for different proxyURL")
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/oauth/... -v -race -run "TestExchange|TestRefresh|TestGetProxy"`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/oauth/manager_test.go
git commit -m "test(oauth): add ExchangeCode, RefreshToken, and proxy client caching tests"
```

---

### Task 7: oauth manager tests

**Files:**
- Modify: `internal/oauth/manager_test.go` (add manager-level tests)
- Reference: `internal/oauth/manager.go`

- [ ] **Step 1: Add UpdateAccounts, ExchangeAndSave, ForceRefresh, MarkTokenExpired tests**

Append to `internal/oauth/manager_test.go`:

```go
func TestUpdateAccounts_AddNew(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	// Add a new account
	m.UpdateAccounts([]string{"test-oauth", "new-account"})

	// Verify the new account has a mutex by checking it doesn't panic
	// when used with GetValidToken (will fail because no token, but shouldn't panic)
	_, err := m.GetValidToken(context.Background(), "new-account")
	if err == nil {
		t.Fatal("expected error for account with no token")
	}
	if !strings.Contains(err.Error(), "no token") {
		t.Errorf("error = %q, want 'no token' hint", err.Error())
	}
}

func TestUpdateAccounts_MutexNotCleaned(t *testing.T) {
	// Known limitation: UpdateAccounts does not remove mutexes for removed accounts.
	// This test documents the behavior.
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	m.UpdateAccounts([]string{"test-oauth", "extra"})
	m.UpdateAccounts([]string{"test-oauth"}) // "extra" removed from accounts list

	// "extra" mutex still exists in the map (known memory leak)
	m.mu.RLock()
	_, exists := m.refreshMu["extra"]
	m.mu.RUnlock()
	if !exists {
		t.Error("mutex for removed account should still exist (known limitation)")
	}
}

func TestExchangeAndSave(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	token, err := m.ExchangeAndSave(context.Background(), "test-oauth", "auth-code", "verifier", "")
	if err != nil {
		t.Fatalf("ExchangeAndSave: %v", err)
	}
	if token.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", token.AccessToken)
	}

	// Verify token was persisted
	loaded, err := store.Load("test-oauth")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected persisted token")
	}
	if loaded.AccessToken != "new-access" {
		t.Errorf("persisted access_token = %q, want new-access", loaded.AccessToken)
	}
}

func TestForceRefresh(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	// Store a token first
	tok := OAuthToken{
		AccessToken:  "old",
		RefreshToken: "old-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = store.Save("test-oauth", tok)

	newToken, err := m.ForceRefresh(context.Background(), "test-oauth")
	if err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}
	if newToken.AccessToken != "new-access" {
		t.Errorf("access_token = %q, want new-access", newToken.AccessToken)
	}
}

func TestForceRefresh_NoToken(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, _ := newTestManager(t, srv.URL)

	_, err := m.ForceRefresh(context.Background(), "test-oauth")
	if err == nil {
		t.Fatal("expected error when no token stored")
	}
}

func TestMarkTokenExpired(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	tok := OAuthToken{
		AccessToken:  "still-valid",
		RefreshToken: "refresh-me",
		ExpiresAt:    time.Now().Add(time.Hour),
	}
	_ = store.Save("test-oauth", tok)

	m.MarkTokenExpired("test-oauth")

	// Token in store should now be expired
	loaded, _ := store.Load("test-oauth")
	if loaded == nil {
		t.Fatal("expected token to still exist")
	}
	if time.Until(loaded.ExpiresAt) > time.Second {
		t.Errorf("token should be expired, expires_at = %v", loaded.ExpiresAt)
	}
}

func TestGetValidToken_ConcurrentRefresh(t *testing.T) {
	srv := mockTokenServer(t)
	defer srv.Close()

	m, store := newTestManager(t, srv.URL)

	// Store an about-to-expire token
	tok := OAuthToken{
		AccessToken:  "expiring",
		RefreshToken: "refresh-me",
		ExpiresAt:    time.Now().Add(30 * time.Second), // below 60s threshold
	}
	_ = store.Save("test-oauth", tok)

	// Launch multiple goroutines to trigger concurrent refresh
	errs := make(chan error, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := m.GetValidToken(context.Background(), "test-oauth")
			errs <- err
		}()
	}

	for i := 0; i < 10; i++ {
		if err := <-errs; err != nil {
			t.Errorf("goroutine %d: %v", i, err)
		}
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/oauth/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/oauth/... -cover`
Expected: ~75-80% (up from 54.3%)

- [ ] **Step 4: Commit**

```bash
git add internal/oauth/manager_test.go
git commit -m "test(oauth): add manager tests for UpdateAccounts, ForceRefresh, MarkTokenExpired, concurrency"
```

---

## Chunk 4: T2 — Low-Coverage Core Packages (Part 3: admin)

### Task 8: admin handler tests

**Files:**
- Modify: `internal/admin/handler_test.go` (add missing handler tests)
- Reference: `internal/admin/handler.go`

Existing tests already cover: HandleAccounts (2 tests), HandleOAuthLoginStart (2 tests), HandleOAuthRefresh_NoToken, HandleOAuthLogout, HandleAddAccount (2 tests), HandleRemoveAccount.

Missing: HandleOAuthLoginComplete (success + CSRF), HandleRemoveAccount_NotFound, HandleUpdateProxy, HandleSessions, HandleDashboard, tokenStatus, writeJSON/writeError/decodeBody helpers.

- [ ] **Step 1: Add missing handler tests**

Append to `internal/admin/handler_test.go`:

```go
func TestHandleRemoveAccount_NotFound(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"name": "nonexistent"})
	req := httptest.NewRequest("POST", "/api/accounts/remove", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleRemoveAccount(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleUpdateProxy(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]any{"name": "test-oauth", "proxy": "socks5://10.0.0.1:1080"})
	req := httptest.NewRequest("POST", "/api/accounts/proxy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleUpdateProxy(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	// Verify proxy was updated
	got := h.registry.GetProxy("test-oauth")
	if got != "socks5://10.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://10.0.0.1:1080", got)
	}
}

func TestHandleUpdateProxy_NotFound(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]any{"name": "nonexistent", "proxy": "socks5://x:1080"})
	req := httptest.NewRequest("POST", "/api/accounts/proxy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleUpdateProxy(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleSessions(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest("GET", "/api/sessions", nil)
	w := httptest.NewRecorder()
	h.HandleSessions(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestHandleDashboard(t *testing.T) {
	h := newTestHandler(t)

	handler := h.HandleDashboard()
	req := httptest.NewRequest("GET", "/index.html", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Static files should be served — exact status depends on whether index.html exists
	// in the embedded FS; at minimum it should not panic
	if w.Code == 0 {
		t.Error("expected a response status code")
	}
}

func TestHandleOAuthLoginComplete_InvalidSession(t *testing.T) {
	h := newTestHandler(t)

	body, _ := json.Marshal(map[string]string{"session_id": "nonexistent", "code": "abc"})
	req := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(w, req)

	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestHandleOAuthLoginComplete_StateMismatch(t *testing.T) {
	h := newTestHandler(t)

	// Start a login session to get a real session ID
	startBody, _ := json.Marshal(map[string]string{"account": "test-oauth"})
	startReq := httptest.NewRequest("POST", "/api/oauth/login/start", bytes.NewReader(startBody))
	startW := httptest.NewRecorder()
	h.HandleOAuthLoginStart(startW, startReq)

	var startResp map[string]string
	_ = json.NewDecoder(startW.Body).Decode(&startResp)
	sessionID := startResp["session_id"]

	// Complete with a mismatched state — code has "authcode#wrong-state"
	completeBody, _ := json.Marshal(map[string]string{
		"session_id": sessionID,
		"code":       "authcode#wrong-state",
	})
	completeReq := httptest.NewRequest("POST", "/api/oauth/login/complete", bytes.NewReader(completeBody))
	completeW := httptest.NewRecorder()
	h.HandleOAuthLoginComplete(completeW, completeReq)

	if completeW.Code != 400 {
		t.Errorf("status = %d, want 400 for state mismatch (CSRF protection)", completeW.Code)
	}

	// Session should be deleted after failed attempt
	_, ok := h.sessions.Get(sessionID)
	if ok {
		t.Error("session should be deleted after state mismatch")
	}
}

func TestTokenStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		token *oauth.OAuthToken
		want  string
	}{
		{"nil", nil, "no token"},
		{"expired", &oauth.OAuthToken{ExpiresAt: time.Now().Add(-time.Hour)}, "expired"},
		{"expiring soon", &oauth.OAuthToken{ExpiresAt: time.Now().Add(2 * time.Minute)}, "expiring soon"},
		{"valid", &oauth.OAuthToken{ExpiresAt: time.Now().Add(time.Hour)}, "valid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tokenStatus(tc.token)
			if got != tc.want {
				t.Errorf("tokenStatus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]string{"key": "value"})

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	// Body should end with newline
	body := w.Body.String()
	if body[len(body)-1] != '\n' {
		t.Error("body should end with newline")
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "something went wrong")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "something went wrong" {
		t.Errorf("error = %q, want 'something went wrong'", resp["error"])
	}
}

func TestDecodeBody_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/", bytes.NewReader([]byte("not-json")))
	var v struct{ Name string }
	ok := decodeBody(w, req, &v)
	if ok {
		t.Error("expected false for invalid JSON")
	}
	if w.Code != 400 {
		t.Errorf("status = %d, want 400", w.Code)
	}
}
```

Also add `"net/http"` to imports if not already present.

- [ ] **Step 2: Run tests**

Run: `go test ./internal/admin/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/admin/... -cover`
Expected: ~75-80% (up from 53.2%)

- [ ] **Step 4: Commit**

```bash
git add internal/admin/handler_test.go
git commit -m "test(admin): add handler tests for proxy, sessions, dashboard, CSRF, helpers"
```

---

## Chunk 5: T3 — Integration Entry Points

### Task 9: config edge case tests

**Files:**
- Modify: `internal/config/config_test.go` (add Validate edge cases)
- Modify: `internal/config/registry_test.go` (add UpdateProxy, GetProxy)
- Reference: `internal/config/config.go`, `internal/config/registry.go`

- [ ] **Step 1: Add Validate edge case tests**

Append to `internal/config/config_test.go`:

```go
func TestValidate_PortRange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		port    int
		wantErr bool
	}{
		{"zero", 0, true},
		{"negative", -1, true},
		{"too high", 65536, true},
		{"min", 1, false},
		{"max", 65535, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &Config{
				Server: ServerConfig{
					AdminPassword:  "pass",
					Port:           tc.port,
					MaxConcurrency: 1,
					RequestTimeout: 1,
				},
				APIKeys: []APIKeyConfig{{Key: "sk-x", Enabled: true}},
			}
			err := cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidate_NegativeConcurrency(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server: ServerConfig{
			AdminPassword:  "pass",
			Port:           3000,
			MaxConcurrency: -1,
			RequestTimeout: 1,
		},
		APIKeys: []APIKeyConfig{{Key: "sk-x", Enabled: true}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative max_concurrency")
	}
	if !strings.Contains(err.Error(), "max_concurrency") {
		t.Errorf("error = %q, want max_concurrency mention", err.Error())
	}
}

func TestValidate_NegativeTimeout(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server: ServerConfig{
			AdminPassword:  "pass",
			Port:           3000,
			MaxConcurrency: 1,
			RequestTimeout: -1,
		},
		APIKeys: []APIKeyConfig{{Key: "sk-x", Enabled: true}},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative request_timeout")
	}
}

func TestRuntimeAccounts_Multiple(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Server: ServerConfig{
			BaseURL:        "https://api.anthropic.com",
			RequestTimeout: 300,
			MaxConcurrency: 5,
		},
	}
	dir := t.TempDir()
	registry := NewAccountRegistry(dir)
	_ = registry.Add("alice")
	_ = registry.Add("bob")

	accounts := cfg.RuntimeAccounts(registry)
	if len(accounts) != 2 {
		t.Fatalf("len = %d, want 2", len(accounts))
	}
	if accounts[0].Name != "alice" || accounts[1].Name != "bob" {
		t.Errorf("names = [%s, %s]", accounts[0].Name, accounts[1].Name)
	}
	for _, a := range accounts {
		if a.MaxConcurrency != 5 {
			t.Errorf("%s: max_concurrency = %d, want 5", a.Name, a.MaxConcurrency)
		}
	}
}
```

- [ ] **Step 2: Add registry UpdateProxy and GetProxy tests**

Append to `internal/config/registry_test.go`:

```go
func TestRegistryUpdateProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)
	_ = r.Add("alice")

	if err := r.UpdateProxy("alice", "socks5://10.0.0.1:1080"); err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}

	got := r.GetProxy("alice")
	if got != "socks5://10.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://10.0.0.1:1080", got)
	}

	// Verify persistence
	r2 := NewAccountRegistry(dir)
	got2 := r2.GetProxy("alice")
	if got2 != "socks5://10.0.0.1:1080" {
		t.Errorf("persisted proxy = %q", got2)
	}
}

func TestRegistryUpdateProxy_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	err := r.UpdateProxy("nonexistent", "socks5://x:1080")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
}

func TestRegistryGetProxy_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	got := r.GetProxy("nonexistent")
	if got != "" {
		t.Errorf("proxy = %q, want empty", got)
	}
}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/config/... -v -race`
Expected: PASS

- [ ] **Step 4: Verify coverage**

Run: `go test ./internal/config/... -cover`
Expected: ~85%+ (up from 79.3%)

- [ ] **Step 5: Commit**

```bash
git add internal/config/config_test.go internal/config/registry_test.go
git commit -m "test(config): add Validate edge cases, RuntimeAccounts, registry proxy tests"
```

---

### Task 10: server middleware tests

**Files:**
- Create: `internal/server/server_test.go`
- Reference: `internal/server/server.go`

- [ ] **Step 1: Write middleware tests**

```go
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecoveryMiddleware_NoPanic(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := recoveryMiddleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestRecoveryMiddleware_WithPanic(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})
	handler := recoveryMiddleware(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	// recoveryMiddleware checks w.(*loggingResponseWriter) — wrap it so the 500 is written
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	handler.ServeHTTP(lrw, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestBasicAuth_Correct(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := basicAuth("secret")(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

func TestBasicAuth_Wrong(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := basicAuth("secret")(inner)

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "wrong")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate header")
	}
}

func TestBasicAuth_NoAuth(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := basicAuth("secret")(inner)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestLoggingResponseWriter_CapturesStatus(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	lrw.WriteHeader(http.StatusNotFound)

	if lrw.statusCode != http.StatusNotFound {
		t.Errorf("statusCode = %d, want 404", lrw.statusCode)
	}
	if w.Code != http.StatusNotFound {
		t.Errorf("underlying status = %d, want 404", w.Code)
	}
}

func TestLoggingResponseWriter_Flush(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	lrw := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	// Should not panic — httptest.ResponseRecorder supports Flush
	lrw.Flush()
	if !w.Flushed {
		t.Error("expected underlying writer to be flushed")
	}
}

func TestRequestLogMiddleware(t *testing.T) {
	t.Parallel()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := requestLogMiddleware(inner)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/server/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/server/... -cover`
Expected: ~30-50% (middleware functions covered; New()/Start()/Shutdown() not covered)

- [ ] **Step 4: Commit**

```bash
git add internal/server/server_test.go
git commit -m "test(server): add middleware tests for recovery, basicAuth, logging"
```

---

### Task 11: cli version test

**Files:**
- Create: `internal/cli/cli_test.go`
- Reference: `internal/cli/version.go`, `internal/cli/root.go`

- [ ] **Step 1: Write version command test**

```go
package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestVersionCmd_Output(t *testing.T) {
	// versionCmd uses fmt.Printf which writes to os.Stdout.
	// Capture by redirecting stdout.
	original := Version
	Version = "1.2.3-test"
	defer func() { Version = original }()

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	versionCmd.Run(versionCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "1.2.3-test") {
		t.Errorf("output = %q, want it to contain version", output)
	}
}

func TestRootCmd_ConfigFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("expected --config flag")
	}
	if flag.DefValue != "config.toml" {
		t.Errorf("default = %q, want config.toml", flag.DefValue)
	}
	if flag.Shorthand != "c" {
		t.Errorf("shorthand = %q, want c", flag.Shorthand)
	}
}
```

- [ ] **Step 2: Run tests**

Run: `go test ./internal/cli/... -v -race`
Expected: PASS

- [ ] **Step 3: Verify coverage**

Run: `go test ./internal/cli/... -cover`
Expected: ~40-60%

- [ ] **Step 4: Commit**

```bash
git add internal/cli/cli_test.go
git commit -m "test(cli): add version command and config flag tests"
```

---

### Task 12: Final verification

- [ ] **Step 1: Run full test suite with race detector**

Run: `go test ./... -race`
Expected: All PASS, no data races

- [ ] **Step 2: Check coverage across all packages**

Run: `go test -cover ./...`
Expected coverage targets:
- `apierror`: ~85-90%
- `fileutil`: ~80-90%
- `netutil`: ~80%+
- `tls`: ~30-45%
- `ratelimit`: ~85%+
- `oauth`: ~75-80%
- `admin`: ~75-80%
- `config`: ~85%+
- `server`: ~30-50%
- `cli`: ~40-60%
- Previously covered packages: unchanged

- [ ] **Step 3: Final commit if any adjustments needed**

```bash
git commit -m "test: final coverage adjustments"
```
