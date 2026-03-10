# ccproxy Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-binary Go proxy that pools Anthropic OAuth accounts for team sharing, with full Claude CLI impersonation, load-aware scheduling, and embedded admin dashboard.

**Architecture:** Single Go binary using chi router, embedded SQLite (modernc.org/sqlite), and embed.FS for dashboard. Core modules: config, auth, disguise engine (6-layer impersonation), load balancer (session-sticky + load-aware), retry/failover, OAuth manager (PKCE + encrypted storage), SSE streaming, and observability.

**Tech Stack:** Go 1.23+, chi, cobra, modernc.org/sqlite, utls, golang.org/x/crypto (AES-GCM, Argon2), fsnotify, BurntSushi/toml

**Spec:** `docs/superpowers/specs/2026-03-10-ccproxy-design.md`

---

## Chunk 1: Project Scaffold & Config

### Task 1: Initialize Go module and project structure

**Files:**
- Create: `go.mod`
- Create: `cmd/ccproxy/main.go`
- Create: `Makefile`
- Create: `.gitignore`
- Create: `config.toml.example`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/binn/ZedProjects/token-run-workspace/ccproxy
go mod init github.com/binn/ccproxy
```

- [ ] **Step 2: Create main.go entry point (minimal)**

Create `cmd/ccproxy/main.go`:
```go
package main

import (
	"fmt"
	"os"

	"github.com/binn/ccproxy/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 3: Create CLI skeleton**

Create `internal/cli/root.go`:
```go
package cli

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	Version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "ccproxy",
	Short: "Claude API proxy with CLI impersonation",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.toml", "config file path")
}

func Execute() error {
	return rootCmd.Execute()
}
```

- [ ] **Step 4: Create Makefile**

Create `Makefile`:
```makefile
.PHONY: build run test clean

VERSION ?= dev
LDFLAGS := -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/ccproxy ./cmd/ccproxy

run: build
	./bin/ccproxy start

test:
	go test ./... -v -race

clean:
	rm -rf bin/ data/
```

- [ ] **Step 5: Create .gitignore**

Create `.gitignore`:
```
bin/
data/
*.db
oauth_tokens.json
config.toml
```

- [ ] **Step 6: Create config.toml.example**

Create `config.toml.example` with the full config structure from the design spec (Section 10).

- [ ] **Step 7: Install dependencies and verify build**

```bash
go get github.com/spf13/cobra
go mod tidy
go build ./cmd/ccproxy
```

Expected: builds without errors.

- [ ] **Step 8: Commit**

```bash
git init
git add -A
git commit -m "feat: initialize project scaffold with CLI skeleton"
```

---

### Task 2: Config loading and validation

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write config test**

Create `internal/config/config_test.go`:
```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	os.WriteFile(path, []byte(`
[server]
host = "127.0.0.1"
port = 3000
log_level = "info"

[[api_keys]]
key = "sk-test-001"
name = "test"
enabled = true

[[instances]]
name = "test-instance"
auth_mode = "bearer"
api_key = "sk-ant-test"
priority = 1
weight = 100
max_concurrency = 5
base_url = "https://api.anthropic.com"
request_timeout = 300
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Server.Port != 3000 {
		t.Errorf("expected port 3000, got %d", cfg.Server.Port)
	}
	if len(cfg.APIKeys) != 1 {
		t.Errorf("expected 1 api key, got %d", len(cfg.APIKeys))
	}
	if len(cfg.Instances) != 1 {
		t.Errorf("expected 1 instance, got %d", len(cfg.Instances))
	}
}

func TestLoadConfig_Validation(t *testing.T) {
	dir := t.TempDir()

	// No API keys
	path := filepath.Join(dir, "no_keys.toml")
	os.WriteFile(path, []byte(`
[server]
port = 3000
[[instances]]
name = "test"
auth_mode = "bearer"
api_key = "sk-test"
`), 0644)
	_, err := Load(path)
	if err == nil {
		t.Error("expected validation error for missing api_keys")
	}

	// No instances
	path2 := filepath.Join(dir, "no_instances.toml")
	os.WriteFile(path2, []byte(`
[server]
port = 3000
[[api_keys]]
key = "sk-test"
name = "test"
enabled = true
`), 0644)
	_, err = Load(path2)
	if err == nil {
		t.Error("expected validation error for missing instances")
	}

	// OAuth instance without provider
	path3 := filepath.Join(dir, "no_provider.toml")
	os.WriteFile(path3, []byte(`
[server]
port = 3000
[[api_keys]]
key = "sk-test"
name = "test"
enabled = true
[[instances]]
name = "test"
auth_mode = "oauth"
oauth_provider = "anthropic"
`), 0644)
	_, err = Load(path3)
	if err == nil {
		t.Error("expected validation error for missing oauth_provider config")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/config/ -v
```
Expected: FAIL (package doesn't exist yet)

- [ ] **Step 3: Implement config module**

Create `internal/config/config.go` with:
- `Config` struct with all nested types: `ServerConfig`, `APIKeyConfig`, `InstanceConfig`, `OAuthProviderConfig`, `ObservabilityConfig`
- `Load(path string) (*Config, error)` — parse TOML, apply defaults, validate
- `Validate() error` — check at least 1 API key, 1 instance, OAuth instances reference valid providers, bearer instances have api_key
- Default values: host="127.0.0.1", port=3000, log_level="info", request_timeout=300, max_concurrency=5, base_url="https://api.anthropic.com", retention_days=7

Key types:
```go
type Config struct {
	Server         ServerConfig         `toml:"server"`
	APIKeys        []APIKeyConfig       `toml:"api_keys"`
	Instances      []InstanceConfig     `toml:"instances"`
	OAuthProviders []OAuthProviderConfig `toml:"oauth_providers"`
	Observability  ObservabilityConfig  `toml:"observability"`
}

type InstanceConfig struct {
	Name            string `toml:"name"`
	AuthMode        string `toml:"auth_mode"`        // "oauth" | "bearer"
	OAuthProvider   string `toml:"oauth_provider"`
	APIKey          string `toml:"api_key"`
	Priority        int    `toml:"priority"`
	Weight          int    `toml:"weight"`
	MaxConcurrency  int    `toml:"max_concurrency"`
	BaseURL         string `toml:"base_url"`
	RequestTimeout  int    `toml:"request_timeout"`   // seconds
	TLSFingerprint  bool   `toml:"tls_fingerprint"`
	Enabled         *bool  `toml:"enabled"`           // default true
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/config/ -v -race
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/ go.mod go.sum
git commit -m "feat: add config loading with TOML parsing and validation"
```

---

### Task 3: CLI commands (start, version, test)

**Files:**
- Create: `internal/cli/start.go`
- Create: `internal/cli/version.go`
- Create: `internal/cli/test_config.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Implement version command**

Create `internal/cli/version.go`:
```go
package cli

import (
	"fmt"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("ccproxy %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
```

- [ ] **Step 2: Implement test command (config validation)**

Create `internal/cli/test_config.go`:
```go
package cli

import (
	"fmt"
	"github.com/binn/ccproxy/internal/config"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Validate configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
		fmt.Printf("Config OK: %d api keys, %d instances\n", len(cfg.APIKeys), len(cfg.Instances))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
```

- [ ] **Step 3: Implement start command (stub for now)**

Create `internal/cli/start.go` — loads config, prints "starting server on host:port", exits. Will be filled in later when server module exists.

- [ ] **Step 4: Verify CLI works**

```bash
go build -o bin/ccproxy ./cmd/ccproxy
./bin/ccproxy version
./bin/ccproxy test -c config.toml.example
```

- [ ] **Step 5: Commit**

```bash
git add internal/cli/
git commit -m "feat: add CLI commands (start, test, version)"
```

---

## Chunk 2: Auth, Session & Observability Foundation

### Task 4: Auth middleware

**Files:**
- Create: `internal/auth/middleware.go`
- Create: `internal/auth/middleware_test.go`

- [ ] **Step 1: Write auth test**

Test cases:
- Missing Authorization header → 401
- Invalid Bearer token → 401
- Valid token → passes, injects `AuthInfo` into context
- Disabled API key → 401
- Constant-time comparison (verify via test structure, not timing)

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement auth middleware**

Use `subtle.ConstantTimeCompare` for token validation. Extract bearer token from `Authorization: Bearer <token>` header. On success, store `AuthInfo{APIKeyName string}` in request context.

```go
type AuthInfo struct {
	APIKeyName string
}

type contextKey string
const authInfoKey contextKey = "auth_info"

func Middleware(apiKeys []config.APIKeyConfig) func(http.Handler) http.Handler
func GetAuthInfo(ctx context.Context) (AuthInfo, bool)
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/auth/
git commit -m "feat: add bearer token auth middleware with constant-time comparison"
```

---

### Task 5: Session ID extraction

**Files:**
- Create: `internal/session/session.go`
- Create: `internal/session/session_test.go`

- [ ] **Step 1: Write session test**

Test cases:
- Extract session UUID from `user_{hex}_account__session_{uuid}` format
- Return empty when format doesn't match
- Compose session key: `apiKeyName:sessionID` or just `apiKeyName`

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement session module**

```go
var sessionRe = regexp.MustCompile(`session_([a-f0-9-]{36})$`)

func ExtractSessionID(userID string) string
func ComposeSessionKey(apiKeyName, sessionID string) string
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/session/
git commit -m "feat: add session ID extraction from metadata.user_id"
```

---

### Task 6: SQLite observability (request logger)

**Files:**
- Create: `internal/observability/logger.go`
- Create: `internal/observability/logger_test.go`
- Create: `internal/observability/stats.go`
- Create: `migrations/001_init.sql`

- [ ] **Step 1: Create SQL migration**

Create `migrations/001_init.sql` with the schema from design spec Section 8.1. Include indexes on timestamp, api_key_name, instance_name, session_id.

- [ ] **Step 2: Write logger test**

Test cases:
- Initialize DB, run migrations
- Log a request event, query it back
- Verify token counts are stored correctly
- Test auto-cleanup of old records

- [ ] **Step 3: Run test to verify it fails**

- [ ] **Step 4: Implement RequestLogger**

```go
type RequestEvent struct {
	RequestID                string
	APIKeyName               string
	InstanceName             string
	Model                    string
	Status                   string  // success|failure|business_error|timeout
	ErrorType                string
	ErrorMessage             string
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
	DurationMs               int64
	SessionID                string
}

type RequestLogger struct {
	db     *sql.DB
	events chan RequestEvent  // buffered channel, cap 10000
}

func NewRequestLogger(dbPath string) (*RequestLogger, error)
func (l *RequestLogger) Log(event RequestEvent)       // non-blocking send to channel
func (l *RequestLogger) Close()                        // drain channel, close db
```

Background goroutine reads from channel and batch-inserts into SQLite.

- [ ] **Step 5: Implement stats queries**

```go
type Stats struct {
	db *sql.DB
}

func (s *Stats) TokenUsageByInstance(hours int) ([]InstanceUsage, error)
func (s *Stats) RecentRequests(limit int) ([]RequestRecord, error)
func (s *Stats) Cleanup(retentionDays int) (int64, error)
```

- [ ] **Step 6: Run tests, verify pass**

- [ ] **Step 7: Commit**

```bash
git add internal/observability/ migrations/
git commit -m "feat: add SQLite request logger with async writes and stats queries"
```

---

## Chunk 3: Disguise Engine

### Task 7: Claude Code client detector

**Files:**
- Create: `internal/disguise/detector.go`
- Create: `internal/disguise/detector_test.go`

- [ ] **Step 1: Write detector test**

Test cases:
- Real Claude Code request (all signals present) → detected
- Non-Claude-Code request (curl) → not detected
- Partial signals (only UA matches) → not detected (need multiple signals)
- System prompt similarity (Dice coefficient) works correctly

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement detector**

```go
func IsClaudeCodeClient(headers http.Header, body []byte) bool
func diceCoefficient(a, b string) float64
```

Multi-dimensional check:
1. User-Agent regex: `^claude-cli/\d+\.\d+\.\d+`
2. X-App == "cli"
3. anthropic-beta contains "claude-code-20250219"
4. metadata.user_id matches pattern
5. System prompt similarity ≥ 0.5

Require at least 3 of 5 signals to match.

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/disguise/detector.go internal/disguise/detector_test.go
git commit -m "feat: add Claude Code client detector with multi-signal validation"
```

---

### Task 8: HTTP headers & beta tokens

**Files:**
- Create: `internal/disguise/headers.go`
- Create: `internal/disguise/beta.go`
- Create: `internal/disguise/headers_test.go`

- [ ] **Step 1: Write headers/beta test**

Test cases:
- `ApplyHeaders(req)` sets all 11 default headers
- `x-stainless-helper-method: stream` added for streaming requests
- `BetaHeader(model, hasTools, isOAuth)` returns correct combination for:
  - Opus + tools + OAuth → full set with oauth beta
  - Haiku + no tools + OAuth → haiku-specific set
  - Sonnet + tools + API Key → no oauth beta
  - count_tokens → includes token-counting beta

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement headers module**

```go
// headers.go
var DefaultHeaders = map[string]string{...}  // 11 headers from spec
func ApplyHeaders(req *http.Request, isStream bool)

// beta.go
const (
	BetaClaudeCode        = "claude-code-20250219"
	BetaOAuth             = "oauth-2025-04-20"
	BetaAdaptiveThinking  = "adaptive-thinking-2026-01-28"
	BetaContextManagement = "context-management-2025-06-27"
	BetaPromptCaching     = "prompt-caching-scope-2026-01-05"
	BetaEffort            = "effort-2025-11-24"
	BetaInterleavedThinking = "interleaved-thinking-2025-05-14"
	BetaTokenCounting     = "token-counting-2024-11-01"
)

func BetaHeader(model string, hasTools bool, isOAuth bool) string
func IsHaikuModel(model string) bool
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/disguise/headers.go internal/disguise/beta.go internal/disguise/headers_test.go
git commit -m "feat: add HTTP header impersonation and anthropic-beta token management"
```

---

### Task 9: Metadata generation & model ID mapping

**Files:**
- Create: `internal/disguise/metadata.go`
- Create: `internal/disguise/models.go`
- Create: `internal/disguise/metadata_test.go`

- [ ] **Step 1: Write test**

Test cases:
- `GenerateUserID()` matches format `user_{64hex}_account__session_{uuid}`
- `NormalizeModelID("claude-sonnet-4-5")` → `"claude-sonnet-4-5-20250929"`
- `DenormalizeModelID("claude-sonnet-4-5-20250929")` → `"claude-sonnet-4-5"`
- Unknown models pass through unchanged

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement metadata and models**

```go
// metadata.go
func GenerateClientID() string    // crypto/rand 32 bytes → hex
func GenerateUserID(sessionSeed string) string  // user_{clientID}_account__session_{uuid}

// models.go
var ModelIDOverrides = map[string]string{
	"claude-sonnet-4-5": "claude-sonnet-4-5-20250929",
	"claude-opus-4-5":   "claude-opus-4-5-20251101",
	"claude-haiku-4-5":  "claude-haiku-4-5-20251001",
}
var ModelIDReverseOverrides = map[string]string{...}  // reverse of above

func NormalizeModelID(id string) string    // short → long
func DenormalizeModelID(id string) string  // long → short
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/disguise/metadata.go internal/disguise/models.go internal/disguise/metadata_test.go
git commit -m "feat: add metadata.user_id generation and model ID mapping"
```

---

### Task 10: Disguise engine (orchestrator)

**Files:**
- Create: `internal/disguise/engine.go`
- Create: `internal/disguise/engine_test.go`

- [ ] **Step 1: Write engine test**

Test cases:
- OAuth instance + non-Claude-Code client → all 6 layers applied
- OAuth instance + real Claude Code client → no disguise (pass-through)
- Bearer instance → no disguise regardless of client
- System prompt injection: when no existing prompt → injected
- System prompt injection: when Claude Code prompt already present → not injected
- System prompt injection: Haiku model → not injected
- URL has `?beta=true` appended

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement engine**

```go
type Engine struct{}

// Apply modifies the request in-place for Claude CLI impersonation.
// Returns true if disguise was applied.
func (e *Engine) Apply(req *http.Request, body []byte, instance *config.InstanceConfig, isStream bool) ([]byte, bool)

// ApplyResponseModelID reverses model ID mapping on response body.
func (e *Engine) ApplyResponseModelID(body []byte) []byte
```

Internal flow:
1. Check `shouldDisguise = instance.IsOAuth() && !IsClaudeCodeClient(req.Header, body)`
2. If yes: apply headers, beta, inject system prompt, generate metadata.user_id, normalize model ID, append `?beta=true` to URL
3. Return modified body

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/disguise/engine.go internal/disguise/engine_test.go
git commit -m "feat: add disguise engine orchestrating 6-layer impersonation"
```

---

## Chunk 4: Load Balancer & Retry

### Task 11: Concurrency tracker

**Files:**
- Create: `internal/loadbalancer/concurrency.go`
- Create: `internal/loadbalancer/concurrency_test.go`

- [ ] **Step 1: Write concurrency test**

Test cases:
- Acquire slot → success, LoadRate increases
- Acquire when at max_concurrency → failure
- Release slot → LoadRate decreases
- Stale slot cleanup (15 min TTL)
- LoadRate calculation: `(active + waiting) * 100 / maxConcurrency`
- Concurrent slot acquisition (race test)

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement concurrency tracker**

```go
type ConcurrencyTracker struct {
	mu      sync.Mutex
	slots   map[string]map[string]time.Time  // instanceName → {requestID → acquireTime}
	waiting map[string]int32
}

func NewConcurrencyTracker() *ConcurrencyTracker

func (t *ConcurrencyTracker) Acquire(instanceName, requestID string, maxConcurrency int) (release func(), ok bool)
func (t *ConcurrencyTracker) LoadRate(instanceName string, maxConcurrency int) int
func (t *ConcurrencyTracker) LoadInfo(instanceName string, maxConcurrency int) (active int, waiting int, rate int)
func (t *ConcurrencyTracker) IncrementWaiting(instanceName string)
func (t *ConcurrencyTracker) DecrementWaiting(instanceName string)
func (t *ConcurrencyTracker) CleanupStale(ttl time.Duration)  // remove entries older than ttl
```

Start a background goroutine for stale cleanup every 30 seconds.

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/loadbalancer/concurrency.go internal/loadbalancer/concurrency_test.go
git commit -m "feat: add in-memory concurrency tracker with slot management"
```

---

### Task 12: Load balancer (multi-layer selection + session affinity)

**Files:**
- Create: `internal/loadbalancer/balancer.go`
- Create: `internal/loadbalancer/balancer_test.go`

- [ ] **Step 1: Write balancer test**

Test cases:
- Single instance → always selected
- Multiple instances → selected by priority (lower first)
- Same priority → weighted random distribution (run 1000 times, verify ratio)
- Session sticky: same sessionKey → same instance (within TTL)
- Session expired (>1h) → new selection
- Sticky instance at capacity (LoadRate ≥ 100) → falls through to Layer 2
- All instances at capacity → returns error (fallback queue timeout)
- Exclude failed instances from selection

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement balancer**

```go
type Balancer struct {
	instances   []config.InstanceConfig
	tracker     *ConcurrencyTracker
	sessions    sync.Map  // sessionKey → SessionInfo
	lastUsed    sync.Map  // instanceName → time.Time
}

type SessionInfo struct {
	InstanceName string
	LastRequest  time.Time
}

type SelectResult struct {
	Instance    config.InstanceConfig
	RequestID   string
	Release     func()
}

func NewBalancer(instances []config.InstanceConfig) *Balancer

// SelectInstance implements the 3-layer selection from spec Section 4.1
func (b *Balancer) SelectInstance(sessionKey string, excludeInstances map[string]bool) (*SelectResult, error)

// BindSession updates or creates a sticky session binding
func (b *Balancer) BindSession(sessionKey, instanceName string)

// ClearSession removes a sticky session binding
func (b *Balancer) ClearSession(sessionKey string)

// StartCleanup starts background goroutine for session and stale slot cleanup
func (b *Balancer) StartCleanup(ctx context.Context)

// UpdateInstances atomically replaces instance list (for hot-reload)
func (b *Balancer) UpdateInstances(instances []config.InstanceConfig)
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/loadbalancer/balancer.go internal/loadbalancer/balancer_test.go
git commit -m "feat: add load balancer with session affinity and load-aware selection"
```

---

### Task 13: Retry engine with failover

**Files:**
- Create: `internal/loadbalancer/retry.go`
- Create: `internal/loadbalancer/retry_test.go`

- [ ] **Step 1: Write retry test**

Test cases:
- `ClassifyError(400)` → BusinessError (no retry)
- `ClassifyError(429)` → Failover
- `ClassifyError(503)` → RetryThenFailover
- `ClassifyError(401)` → Failover
- Retry delay calculation: 300ms → 600ms → 1.2s → 2.4s → 3s(max)
- `ExecuteWithRetry` retries 5xx on same instance, then failovers
- `ExecuteWithRetry` returns immediately on 400
- Max 10 instance switches
- Max 3 same-instance retries
- Total retry elapsed time does not exceed 10s

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement retry engine**

```go
type FailureAction int
const (
	ReturnToClient FailureAction = iota  // 400: return directly
	Failover                              // 401,403,429,529: switch instance immediately
	RetryThenFailover                     // 500-504: retry same instance, then failover
)

func ClassifyError(statusCode int) FailureAction

func RetryDelay(attempt int) time.Duration  // exponential backoff

type RetryConfig struct {
	MaxRetryAttempts       int           // 5
	MaxAccountSwitches     int           // 10
	MaxSameInstanceRetries int           // 3
	MaxRetryElapsed        time.Duration // 10s
}

// ExecuteWithRetry runs the request function with retry and failover logic.
// requestFn takes an instance config and returns (response, statusCode, error).
// selectFn picks the next instance, excluding failed ones.
func ExecuteWithRetry(
	ctx context.Context,
	cfg RetryConfig,
	balancer *Balancer,
	sessionKey string,
	requestFn func(instance config.InstanceConfig, requestID string) (resp *http.Response, statusCode int, err error),
) (*http.Response, string, error)  // response, instanceName, error
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/loadbalancer/retry.go internal/loadbalancer/retry_test.go
git commit -m "feat: add retry engine with exponential backoff and failover"
```

---

## Chunk 5: TLS Fingerprint & OAuth

### Task 14: TLS fingerprint dialer

**Files:**
- Create: `internal/tls/fingerprint.go`
- Create: `internal/tls/fingerprint_test.go`

- [ ] **Step 1: Write TLS test**

Test cases:
- `NewFingerprintTransport(true)` creates transport with utls
- `NewFingerprintTransport(false)` creates standard transport
- Verify custom dialer is used when TLS fingerprint is enabled
- Basic HTTPS request succeeds with fingerprinted transport

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement fingerprint dialer**

Port the TLS profile from sub2api's `internal/pkg/tlsfingerprint/dialer.go`:
- 59 cipher suites, 10 curves, 20 signature algorithms
- JA3: `1a28e69016765d92e3b381168d68922c`
- No GREASE (Node.js doesn't use it)

```go
func NewFingerprintTransport(enabled bool) http.RoundTripper
func claudeCLIv2Spec() *utls.ClientHelloSpec  // return the ClientHello spec
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/tls/
git commit -m "feat: add TLS fingerprint dialer mimicking Claude CLI (Node.js 20.x)"
```

---

### Task 15: OAuth PKCE flow

**Files:**
- Create: `internal/oauth/pkce.go`
- Create: `internal/oauth/pkce_test.go`

- [ ] **Step 1: Write PKCE test**

Test cases:
- `GenerateVerifier()` returns 43-128 char base64url string
- `GenerateChallenge(verifier)` returns SHA-256 base64url hash
- `GenerateState()` returns random base64url string
- Challenge can be verified against verifier

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement PKCE**

```go
func GenerateVerifier() string     // 32 bytes → base64url
func GenerateChallenge(verifier string) string  // SHA-256 → base64url
func GenerateState() string        // 16 bytes → base64url
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/pkce.go internal/oauth/pkce_test.go
git commit -m "feat: add PKCE parameter generation for OAuth flow"
```

---

### Task 16: Encrypted token storage

**Files:**
- Create: `internal/oauth/store.go`
- Create: `internal/oauth/store_test.go`

- [ ] **Step 1: Write store test**

Test cases:
- Save token → load token → values match
- Encryption: raw file content is not plaintext
- File permissions are 0600
- Multiple providers can be stored/loaded independently
- Delete provider removes token
- Load from nonexistent file → empty result (no error)

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement token store**

```go
type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope"`
}

type TokenStore struct {
	path string
	key  []byte  // AES-256 key derived from machine identity
	mu   sync.RWMutex
}

func NewTokenStore(dataDir string) (*TokenStore, error)
func (s *TokenStore) Save(providerName string, token OAuthToken) error
func (s *TokenStore) Load(providerName string) (*OAuthToken, error)
func (s *TokenStore) Delete(providerName string) error
func (s *TokenStore) List() ([]string, error)

// Internal: derive key using Argon2 from hostname + username
func deriveKey() ([]byte, error)
func encrypt(plaintext, key []byte) ([]byte, error)
func decrypt(ciphertext, key []byte) ([]byte, error)
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/oauth/store.go internal/oauth/store_test.go
git commit -m "feat: add AES-256-GCM encrypted OAuth token storage"
```

---

### Task 17: OAuth manager (provider + auto-refresh)

**Files:**
- Create: `internal/oauth/provider.go`
- Create: `internal/oauth/manager.go`
- Create: `internal/oauth/manager_test.go`

- [ ] **Step 1: Write manager test**

Test cases:
- `GetValidToken()` when token is fresh → returns cached
- `GetValidToken()` when token expires within 60s → triggers refresh
- `GetValidToken()` when no token → returns error with login instructions
- Concurrent `GetValidToken()` calls only trigger one refresh (mutex)
- `Login()` generates correct authorization URL with PKCE params

Note: Use a mock HTTP server for token exchange tests.

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement OAuth provider**

```go
// provider.go
type AnthropicProvider struct {
	config config.OAuthProviderConfig
	client *http.Client
}

func (p *AnthropicProvider) AuthorizationURL(state, codeChallenge string) string
func (p *AnthropicProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*OAuthToken, error)
func (p *AnthropicProvider) RefreshToken(ctx context.Context, refreshToken string) (*OAuthToken, error)
```

- [ ] **Step 4: Implement OAuth manager**

```go
// manager.go
type Manager struct {
	providers map[string]*AnthropicProvider
	store     *TokenStore
	mu        map[string]*sync.Mutex  // per-provider refresh lock
}

func NewManager(providers []config.OAuthProviderConfig, store *TokenStore) *Manager
func (m *Manager) GetValidToken(ctx context.Context, providerName string) (*OAuthToken, error)
func (m *Manager) Login(providerName string) (authURL string, callbackHandler http.HandlerFunc, err error)
func (m *Manager) Logout(providerName string) error
func (m *Manager) Status(providerName string) (*OAuthToken, error)
func (m *Manager) StartAutoRefresh(ctx context.Context)  // background goroutine every 5 min
```

- [ ] **Step 5: Run tests, verify pass**

- [ ] **Step 6: Commit**

```bash
git add internal/oauth/provider.go internal/oauth/manager.go internal/oauth/manager_test.go
git commit -m "feat: add OAuth manager with PKCE login, token refresh, and auto-refresh"
```

---

## Chunk 6: Proxy Handler & SSE Streaming

### Task 18: SSE streaming forwarder

**Files:**
- Create: `internal/proxy/streaming.go`
- Create: `internal/proxy/streaming_test.go`

- [ ] **Step 1: Write streaming test**

Test cases:
- Parse SSE events from byte stream (event: + data: lines)
- Extract token usage from `message_delta` event
- Forward events transparently (event names and data preserved)
- Handle incomplete chunks (data split across reads)
- Client disconnect (context cancelled) → stop forwarding
- Extract final usage: `(inputTokens, outputTokens, cacheCreation, cacheRead)`

Use a mock SSE server that emits a sequence of events.

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement streaming**

```go
type UsageInfo struct {
	InputTokens              int64
	OutputTokens             int64
	CacheCreationInputTokens int64
	CacheReadInputTokens     int64
}

// ForwardSSE reads SSE events from upstream and writes them to the client.
// Returns usage info extracted from message_delta events.
func ForwardSSE(ctx context.Context, upstream io.Reader, downstream http.ResponseWriter) (*UsageInfo, error)

// Internal: parse SSE event from buffered reader
type sseEvent struct {
	Event string
	Data  string
}
func parseSSEEvents(reader *bufio.Reader) <-chan sseEvent
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/streaming.go internal/proxy/streaming_test.go
git commit -m "feat: add SSE streaming forwarder with token usage extraction"
```

---

### Task 19: Proxy handler

**Files:**
- Create: `internal/proxy/handler.go`
- Create: `internal/proxy/handler_test.go`

- [ ] **Step 1: Write proxy handler test**

Test cases:
- Non-streaming request → JSON response forwarded, usage logged
- Streaming request → SSE forwarded, usage logged
- Disguise applied for OAuth instance + non-Claude-Code client
- Disguise NOT applied for Bearer instance
- Model ID reverse-mapped in response
- Error response mapped correctly (401→502, 429→429, etc.)
- Auth info from middleware available in handler
- Session binding after successful request

Use httptest.Server as mock upstream.

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement proxy handler**

```go
type Handler struct {
	balancer      *loadbalancer.Balancer
	disguise      *disguise.Engine
	oauthManager  *oauth.Manager
	logger        *observability.RequestLogger
	httpClients   map[string]*http.Client  // instanceName → client (with/without TLS fingerprint)
}

func NewHandler(
	instances []config.InstanceConfig,
	balancer *loadbalancer.Balancer,
	disguise *disguise.Engine,
	oauthManager *oauth.Manager,
	logger *observability.RequestLogger,
) *Handler

// ServeHTTP handles POST /v1/messages
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

Handler flow:
1. Read request body
2. Extract model, stream flag, session_id from body
3. Get auth info from context
4. Compose session key
5. Use retry engine to execute request with failover:
   a. Select instance via balancer
   b. Resolve auth (OAuth token or API key)
   c. Apply disguise if needed (modifies body + headers)
   d. Build upstream request (POST to instance.BaseURL + "/v1/messages?beta=true")
   e. Set auth header (x-api-key or Authorization: Bearer)
   f. Send request with instance-specific HTTP client
   g. Handle response (streaming or non-streaming)
6. Log request to observability
7. Bind/update session

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "feat: add proxy handler with disguise, failover, and streaming support"
```

---

## Chunk 7: Server, Admin Dashboard & CLI Integration

### Task 20: HTTP server with routing

**Files:**
- Create: `internal/server/server.go`

- [ ] **Step 1: Implement server**

```go
type Server struct {
	cfg          *config.Config
	httpServer   *http.Server
	balancer     *loadbalancer.Balancer
	disguise     *disguise.Engine
	oauthManager *oauth.Manager
	logger       *observability.RequestLogger
}

func New(cfg *config.Config) (*Server, error)

// Start initializes all components and starts listening
func (s *Server) Start(ctx context.Context) error

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error
```

Router setup:
```go
r := chi.NewRouter()
r.Use(middleware.RealIP)
r.Use(middleware.Logger)
r.Use(middleware.Recoverer)

// API routes (require auth)
r.Group(func(r chi.Router) {
    r.Use(auth.Middleware(cfg.APIKeys))
    r.Post("/v1/messages", proxyHandler.ServeHTTP)
})

// Admin routes (optional basic auth)
r.Group(func(r chi.Router) {
    if cfg.Server.AdminPassword != "" {
        r.Use(adminAuth(cfg.Server.AdminPassword))
    }
    r.Get("/admin/*", adminHandler)
    r.Get("/api/stats", statsHandler)
    r.Get("/api/instances", instancesHandler)
    r.Get("/api/sessions", sessionsHandler)
    r.Get("/api/requests", requestsHandler)
})
```

- [ ] **Step 2: Wire server into start CLI command**

Update `internal/cli/start.go` to load config, create server, handle signals (SIGTERM, SIGINT for graceful shutdown, SIGHUP for config reload).

- [ ] **Step 3: Verify server starts and responds**

```bash
cp config.toml.example config.toml
# Edit config.toml with a bearer instance
go build -o bin/ccproxy ./cmd/ccproxy
./bin/ccproxy start
# In another terminal:
curl -H "Authorization: Bearer sk-ccproxy-001" http://localhost:3000/v1/messages
# Should get an error response (no valid upstream), but shows auth works
```

- [ ] **Step 4: Commit**

```bash
git add internal/server/ internal/cli/start.go
git commit -m "feat: add HTTP server with chi routing and signal handling"
```

---

### Task 21: Admin dashboard

**Files:**
- Create: `internal/admin/handler.go`
- Create: `internal/admin/static/index.html`

- [ ] **Step 1: Create admin API handlers**

```go
// handler.go
type AdminHandler struct {
	stats    *observability.Stats
	balancer *loadbalancer.Balancer
}

func (h *AdminHandler) HandleStats(w http.ResponseWriter, r *http.Request)     // GET /api/stats?hours=24
func (h *AdminHandler) HandleInstances(w http.ResponseWriter, r *http.Request)  // GET /api/instances
func (h *AdminHandler) HandleSessions(w http.ResponseWriter, r *http.Request)   // GET /api/sessions
func (h *AdminHandler) HandleRequests(w http.ResponseWriter, r *http.Request)   // GET /api/requests?limit=100
func (h *AdminHandler) HandleDashboard() http.Handler                           // GET /admin/* (embed.FS)
```

- [ ] **Step 2: Create dashboard HTML**

Create `internal/admin/static/index.html` — a single-page HTML with:
- Token usage chart (grouped by instance, last 24h)
- Instance status table (name, auth_mode, load_rate, active_slots, status)
- Active sessions list
- Recent requests table (last 100)
- Auto-refresh every 30 seconds
- Use vanilla JS + fetch API, no framework needed
- CSS inline for single-file simplicity

- [ ] **Step 3: Wire admin into server**

Add admin routes and embed.FS to server.go.

- [ ] **Step 4: Verify dashboard loads**

```bash
go build -o bin/ccproxy ./cmd/ccproxy && ./bin/ccproxy start
# Open http://localhost:3000/admin/ in browser
```

- [ ] **Step 5: Commit**

```bash
git add internal/admin/
git commit -m "feat: add embedded admin dashboard with stats API"
```

---

### Task 22: Remaining CLI commands

**Files:**
- Create: `internal/cli/stop.go`
- Create: `internal/cli/reload.go`
- Create: `internal/cli/stats.go`
- Create: `internal/cli/oauth.go`

- [ ] **Step 1: Implement stop command**

Write PID to `data/ccproxy.pid` on start. Stop command reads PID and sends SIGTERM.

- [ ] **Step 2: Implement reload command**

Send SIGHUP to running process.

- [ ] **Step 3: Implement stats command**

Connect to SQLite directly and query token usage stats. Format as table output.

- [ ] **Step 4: Implement oauth commands**

```bash
ccproxy oauth login <provider>    # start PKCE flow, open browser
ccproxy oauth status              # show token expiry for all providers
ccproxy oauth refresh <provider>  # force token refresh
ccproxy oauth logout <provider>   # delete stored token
```

- [ ] **Step 5: Verify all commands work**

```bash
./bin/ccproxy version
./bin/ccproxy test -c config.toml
./bin/ccproxy oauth status
./bin/ccproxy stats --hours 24
```

- [ ] **Step 6: Commit**

```bash
git add internal/cli/
git commit -m "feat: add CLI commands (stop, reload, stats, oauth)"
```

---

## Chunk 8: Config Hot-Reload & Integration Testing

### Task 23: Config hot-reload

**Files:**
- Modify: `internal/config/config.go` — add `Watch()` method
- Modify: `internal/server/server.go` — integrate reload

- [ ] **Step 1: Implement config watcher**

```go
// Watch starts watching the config file for changes.
// On change, reloads and validates config, then calls onChange callback.
func Watch(path string, onChange func(*Config)) (stop func(), err error)
```

Use `fsnotify` for file watching. Also handle SIGHUP signal for manual reload.

On reload:
- Validate new config before applying
- Update balancer instances
- Update auth middleware API keys
- Log changes

- [ ] **Step 2: Integrate with server**

Wire `config.Watch` into the server startup. On SIGHUP or file change, reload config and update relevant components.

- [ ] **Step 3: Test hot-reload**

```bash
# Start server
./bin/ccproxy start &
# Modify config.toml (change port or add instance)
# Verify logs show "config reloaded"
# Verify new config takes effect
```

- [ ] **Step 4: Commit**

```bash
git add internal/config/ internal/server/
git commit -m "feat: add config hot-reload via fsnotify and SIGHUP"
```

---

### Task 24: Integration test

**Files:**
- Create: `tests/integration_test.go`

- [ ] **Step 1: Write integration test**

End-to-end test with mock upstream:
1. Start a mock Anthropic API server (httptest)
2. Configure ccproxy to point to mock server
3. Send requests through ccproxy
4. Verify:
   - Auth works (valid/invalid tokens)
   - Non-streaming request forwarded and response returned
   - Streaming request forwarded and SSE events received
   - Disguise headers applied (check mock server received correct headers)
   - Session sticky routing (same session → same instance)
   - Failover on 503 (mock returns 503, ccproxy retries)
   - Request logged in SQLite
   - Stats API returns correct data

- [ ] **Step 2: Run integration tests**

```bash
go test ./tests/ -v -race -timeout 60s
```

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test: add integration tests with mock upstream"
```

---

### Task 25: Error response mapping & Anthropic format

**Files:**
- Create: `internal/proxy/errors.go`
- Create: `internal/proxy/errors_test.go`

- [ ] **Step 1: Write error response test**

Test cases:
- `MapUpstreamError(401)` → 502 with `{"type":"error","error":{"type":"authentication_error","message":"Upstream authentication failed"}}`
- `MapUpstreamError(429)` → 429 with `rate_limit_error`
- `MapUpstreamError(529)` → 503 with `overloaded_error`
- `MapUpstreamError(503)` → 502 with `upstream_error`
- All responses have correct Content-Type: application/json

- [ ] **Step 2: Run test to verify it fails**

- [ ] **Step 3: Implement error mapping**

```go
type AnthropicError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

func MapUpstreamError(statusCode int, upstreamBody []byte) (int, []byte)
func WriteError(w http.ResponseWriter, statusCode int, errType, message string)
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/errors.go internal/proxy/errors_test.go
git commit -m "feat: add Anthropic-style error response mapping"
```

---

### Task 26: Final polish

**Files:**
- Create: `README.md`
- Create: `CLAUDE.md`

- [ ] **Step 1: Create README.md**

Include:
- Project description
- Quick start guide
- Configuration reference
- CLI usage
- Architecture overview

- [ ] **Step 2: Create CLAUDE.md**

Project-specific instructions for Claude Code development.

- [ ] **Step 3: Final build and verify**

```bash
make build
./bin/ccproxy version
./bin/ccproxy test -c config.toml.example
make test
```

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: add README and CLAUDE.md"
```
