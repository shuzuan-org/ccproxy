# OTA Auto-Upgrade Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add self-updating capability to ccproxy — background version checking against GitHub Releases, automatic binary replacement, graceful restart, CLI command, and admin dashboard integration.

**Architecture:** New `internal/updater/` package using `creativeprojects/go-selfupdate` for GitHub Releases integration. Updater is owned by `server.Server`, started with the server's context, and exposed to admin via `admin.Handler`. CLI `upgrade` subcommand for manual upgrades.

**Tech Stack:** Go 1.25, creativeprojects/go-selfupdate, GoReleaser (CI only)

**Spec:** `docs/superpowers/specs/2026-03-17-ota-auto-upgrade-design.md`

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `internal/updater/updater.go` | Updater struct, Start/CheckNow/Apply, status tracking |
| Create | `internal/updater/updater_test.go` | Unit tests for Updater |
| Modify | `internal/config/config.go:19-28` | Add AutoUpdate, UpdateCheckInterval, UpdateRepo to ServerConfig |
| Modify | `internal/config/config.go:113-136` | Add defaults in applyDefaults() |
| Modify | `internal/config/config.go:140+` | Add validation for UpdateCheckInterval |
| Modify | `config.toml.example` | Document new config fields |
| Modify | `internal/cli/root.go` | Pass Version to server.New |
| Create | `internal/cli/upgrade.go` | `ccproxy upgrade` subcommand |
| Create | `internal/cli/upgrade_test.go` | Tests for upgrade command |
| Modify | `internal/server/server.go:23-29` | Add updater field to Server struct |
| Modify | `internal/server/server.go:32-178` | Create Updater in New(), wire to admin, start background loop |
| Modify | `internal/admin/handler.go:22-28` | Add updater field to Handler struct |
| Modify | `internal/admin/handler.go:31-39` | Accept updater in NewHandler() |
| Create | `internal/admin/update_handlers.go` | HandleUpdateStatus/Check/Apply handlers |
| Create | `internal/admin/update_handlers_test.go` | Tests for update API handlers |
| Modify | `internal/observe/metrics.go:87-147` | Add update status to periodic log |
| Modify | `Makefile` | Add release target |
| Create | `.github/workflows/release.yml` | GoReleaser release workflow |
| Create | `.goreleaser.yml` | GoReleaser config |

---

## Chunk 1: Core Updater Package

### Task 1: Add go-selfupdate dependency

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Add dependency**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go get github.com/creativeprojects/go-selfupdate`

- [ ] **Step 2: Tidy**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go mod tidy`

- [ ] **Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: add go-selfupdate dependency"
```

---

### Task 2: Add config fields for auto-update

**Files:**
- Modify: `internal/config/config.go:19-28` (ServerConfig struct)
- Modify: `internal/config/config.go:113-136` (applyDefaults)
- Modify: `internal/config/config.go:140+` (Validate)
- Modify: `config.toml.example`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write failing test for new config defaults**

In `internal/config/config_test.go`, add:

```go
func TestLoad_AutoUpdateDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	os.WriteFile(cfgPath, []byte("[server]\nadmin_password = \"test123\"\n"), 0o600)

	cfg, err := Load(cfgPath)
	require.NoError(t, err)
	assert.NotNil(t, cfg.Server.AutoUpdate)
	assert.True(t, *cfg.Server.AutoUpdate)
	assert.Equal(t, "1h", cfg.Server.UpdateCheckInterval)
	assert.Equal(t, "binn/ccproxy", cfg.Server.UpdateRepo)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/config/... -run TestLoad_AutoUpdateDefaults -v`
Expected: FAIL — fields do not exist

- [ ] **Step 3: Add fields to ServerConfig and helper method**

In `internal/config/config.go`, add to `ServerConfig` struct (after line 27, the LogLevel field):

```go
AutoUpdate          *bool  `toml:"auto_update"`            // nil = true (default); pointer to distinguish unset from false
UpdateCheckInterval string `toml:"update_check_interval"`  // duration string, e.g. "1h", "30m"
UpdateRepo          string `toml:"update_repo"`             // GitHub owner/repo
```

Add helper method after ServerConfig:

```go
// IsAutoUpdateEnabled returns the effective auto_update value (default: true).
func (s ServerConfig) IsAutoUpdateEnabled() bool {
	if s.AutoUpdate == nil {
		return true
	}
	return *s.AutoUpdate
}
```

Add `"time"` to imports if not already present.

- [ ] **Step 4: Add defaults in applyDefaults()**

In `internal/config/config.go`, add at the end of `applyDefaults()` (before closing brace at line 136):

```go
if cfg.Server.AutoUpdate == nil {
	t := true
	cfg.Server.AutoUpdate = &t
}
if cfg.Server.UpdateCheckInterval == "" {
	cfg.Server.UpdateCheckInterval = "1h"
}
if cfg.Server.UpdateRepo == "" {
	cfg.Server.UpdateRepo = "binn/ccproxy"
}
```

- [ ] **Step 5: Add validation for UpdateCheckInterval**

In `internal/config/config.go` `Validate()` method, add before the final `return errors.Join(errs...)`:

```go
if cfg.Server.UpdateCheckInterval != "" {
	d, err := time.ParseDuration(cfg.Server.UpdateCheckInterval)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid update_check_interval %q: %w", cfg.Server.UpdateCheckInterval, err))
	} else if d < 5*time.Minute {
		errs = append(errs, fmt.Errorf("update_check_interval must be >= 5m, got %s", d))
	} else if d > 24*time.Hour {
		errs = append(errs, fmt.Errorf("update_check_interval must be <= 24h, got %s", d))
	}
}
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/config/... -run TestLoad_AutoUpdateDefaults -v`
Expected: PASS

- [ ] **Step 7: Write test for interval validation**

```go
func TestLoad_UpdateCheckIntervalValidation(t *testing.T) {
	tests := []struct {
		name     string
		interval string
		wantErr  bool
	}{
		{"valid 1h", "1h", false},
		{"valid 30m", "30m", false},
		{"too short", "1m", true},
		{"too long", "48h", true},
		{"invalid", "notaduration", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.toml")
			content := fmt.Sprintf("[server]\nadmin_password = \"test123\"\nupdate_check_interval = %q\n", tt.interval)
			os.WriteFile(cfgPath, []byte(content), 0o600)
			_, err := Load(cfgPath)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
```

- [ ] **Step 8: Run validation tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/config/... -run TestLoad_UpdateCheckInterval -v`
Expected: PASS

- [ ] **Step 9: Update config.toml.example**

Add after the `log_level` line (line 9):

```toml
# auto_update = true          # enable background auto-upgrade (default: true)
# update_check_interval = "1h" # check interval, min 5m, max 24h (default: 1h)
# update_repo = "binn/ccproxy" # GitHub owner/repo for update source
```

- [ ] **Step 10: Run all config tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/config/... -v -race`
Expected: ALL PASS

- [ ] **Step 11: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go config.toml.example
git commit -m "feat(config): add auto-update configuration fields"
```

---

### Task 3: Create Updater core

**Files:**
- Create: `internal/updater/updater.go`
- Create: `internal/updater/updater_test.go`

- [ ] **Step 1: Write failing test for Updater creation and status**

Create `internal/updater/updater_test.go`:

```go
package updater

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "binn/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})
	assert.NotNil(t, u)

	status := u.Status()
	assert.Equal(t, "1.0.0", status.CurrentVersion)
	assert.Equal(t, "", status.LatestVersion)
	assert.True(t, status.LastCheck.IsZero())
	assert.True(t, status.AutoUpdate)
}

func TestNew_DevVersion(t *testing.T) {
	u := New(Config{
		CurrentVersion: "dev",
		Repo:           "binn/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})
	assert.NotNil(t, u)

	// Dev version: Start should return immediately without blocking
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	u.Start(ctx) // should not block
}

func TestUpdater_StatusFields(t *testing.T) {
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "binn/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     false,
	})

	status := u.Status()
	assert.False(t, status.AutoUpdate)
	assert.False(t, status.Checking)
	assert.False(t, status.Updating)
}

func TestUpdater_StartRespectsContext(t *testing.T) {
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "binn/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     false, // disabled, so Start returns immediately
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should not block since auto_update is false
	done := make(chan struct{})
	go func() {
		u.Start(ctx)
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(time.Second):
		t.Fatal("Start did not return after context cancel")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/updater/... -run TestNew -v`
Expected: FAIL — package does not exist

- [ ] **Step 3: Implement Updater struct and New()**

Create `internal/updater/updater.go`:

```go
package updater

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creativeprojects/go-selfupdate"
)

// Config holds updater configuration.
type Config struct {
	CurrentVersion string
	Repo           string        // "owner/repo"
	CheckInterval  time.Duration
	AutoUpdate     bool
}

// UpdateStatus represents the current update state.
type UpdateStatus struct {
	CurrentVersion string    `json:"current_version"`
	LatestVersion  string    `json:"latest_version"`
	LastCheck      time.Time `json:"last_check"`
	AutoUpdate     bool      `json:"auto_update"`
	Checking       bool      `json:"checking"`
	Updating       bool      `json:"updating"`
}

// Updater checks for and applies updates from GitHub Releases.
type Updater struct {
	cfg      Config
	isDev    bool
	isDocker bool

	mu        sync.RWMutex
	latest    string
	lastCheck time.Time
	checking  bool
	updating  bool
}

// New creates an Updater. Does not start background checking.
func New(cfg Config) *Updater {
	_, dockerErr := os.Stat("/.dockerenv")
	return &Updater{
		cfg:      cfg,
		isDev:    cfg.CurrentVersion == "dev",
		isDocker: dockerErr == nil,
	}
}

// Status returns the current update status.
func (u *Updater) Status() UpdateStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return UpdateStatus{
		CurrentVersion: u.cfg.CurrentVersion,
		LatestVersion:  u.latest,
		LastCheck:      u.lastCheck,
		AutoUpdate:     u.cfg.AutoUpdate,
		Checking:       u.checking,
		Updating:       u.updating,
	}
}

// Start launches the background update check loop. Blocks until ctx is cancelled.
func (u *Updater) Start(ctx context.Context) {
	if !u.cfg.AutoUpdate || u.isDev || u.isDocker {
		if u.isDev {
			slog.Info("auto-update disabled: dev version")
		} else if u.isDocker {
			slog.Info("auto-update disabled: running in Docker")
		} else {
			slog.Info("auto-update disabled by config")
		}
		return
	}

	slog.Info("auto-update enabled",
		"interval", u.cfg.CheckInterval.String(),
		"repo", u.cfg.Repo,
	)

	ticker := time.NewTicker(u.cfg.CheckInterval)
	defer ticker.Stop()

	// Initial check after a short delay, respecting context cancellation.
	initialDelay := time.NewTimer(30 * time.Second)
	defer initialDelay.Stop()

	select {
	case <-ctx.Done():
		return
	case <-initialDelay.C:
		u.checkAndApply(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.checkAndApply(ctx)
		}
	}
}

// CheckNow performs an immediate version check. Returns the latest version found.
func (u *Updater) CheckNow(ctx context.Context) (string, error) {
	release, _, err := u.findLatest(ctx)
	if err != nil {
		return "", err
	}
	if release == nil {
		return u.cfg.CurrentVersion, nil
	}
	return release.Version(), nil
}

// Apply checks for update and applies it if available. Returns (updated, newVersion, error).
func (u *Updater) Apply(ctx context.Context, force bool) (bool, string, error) {
	u.mu.Lock()
	u.updating = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.updating = false
		u.mu.Unlock()
	}()

	release, updater, err := u.findLatest(ctx)
	if err != nil {
		return false, "", err
	}
	if release == nil {
		return false, u.cfg.CurrentVersion, nil
	}

	if !force && release.LessOrEqual(u.cfg.CurrentVersion) {
		return false, release.Version(), nil
	}

	exe, err := selfupdate.ExecutablePath()
	if err != nil {
		return false, "", fmt.Errorf("find executable path: %w", err)
	}

	if err := updater.UpdateTo(ctx, release, exe); err != nil {
		return false, "", fmt.Errorf("apply update: %w", err)
	}

	slog.Info("update applied",
		"from", u.cfg.CurrentVersion,
		"to", release.Version(),
	)
	return true, release.Version(), nil
}

// Restart sends SIGTERM to the current process to trigger graceful shutdown.
// The existing signal handler in cli/root.go catches SIGTERM, calls srv.Shutdown()
// with a 10-second drain timeout, then exits. Expects systemd Restart=always
// (or similar) to bring up the new binary.
func (u *Updater) Restart() {
	slog.Info("restarting process for update")
	p, err := os.FindProcess(os.Getpid())
	if err != nil {
		slog.Error("failed to find own process", "error", err)
		return
	}
	_ = p.Signal(syscall.SIGTERM)
}

func (u *Updater) checkAndApply(ctx context.Context) {
	updated, newVersion, err := u.Apply(ctx, false)
	if err != nil {
		slog.Warn("auto-update check failed", "error", err)
		return
	}
	if updated {
		slog.Info("auto-update: upgrade successful, restarting",
			"from", u.cfg.CurrentVersion,
			"to", newVersion,
		)
		u.Restart()
	}
}

// findLatest detects the latest release and returns both the release and the
// selfupdate.Updater instance (needed for UpdateTo). Returns (nil, nil, nil)
// if no release is found.
func (u *Updater) findLatest(ctx context.Context) (*selfupdate.Release, *selfupdate.Updater, error) {
	u.mu.Lock()
	u.checking = true
	u.mu.Unlock()
	defer func() {
		u.mu.Lock()
		u.checking = false
		u.lastCheck = time.Now()
		u.mu.Unlock()
	}()

	source, err := selfupdate.NewGitHubSource(selfupdate.GitHubConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("create github source: %w", err)
	}

	updater, err := selfupdate.NewUpdater(selfupdate.Config{
		Source:    source,
		Validator: &selfupdate.ChecksumValidator{UniqueFilename: "checksums.txt"},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create updater: %w", err)
	}

	// ParseSlug accepts "owner/repo" as a single string.
	parts := strings.SplitN(u.cfg.Repo, "/", 2)
	if len(parts) != 2 {
		return nil, nil, fmt.Errorf("invalid repo format %q, expected owner/repo", u.cfg.Repo)
	}
	slug := selfupdate.NewRepositorySlug(parts[0], parts[1])

	release, found, err := updater.DetectLatest(ctx, slug)
	if err != nil {
		return nil, nil, fmt.Errorf("detect latest: %w", err)
	}
	if !found {
		return nil, nil, nil
	}

	u.mu.Lock()
	u.latest = release.Version()
	u.mu.Unlock()

	return release, updater, nil
}
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/updater/... -v -race`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add internal/updater/updater.go internal/updater/updater_test.go
git commit -m "feat(updater): add core updater with GitHub Releases integration"
```

---

## Chunk 2: CLI Command & Server/Admin Integration

### Task 4: Add `ccproxy upgrade` CLI command

**Files:**
- Create: `internal/cli/upgrade.go`
- Create: `internal/cli/upgrade_test.go`

- [ ] **Step 1: Write failing test**

Create `internal/cli/upgrade_test.go`:

```go
package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUpgradeCmd_Registered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "upgrade" {
			found = true
			break
		}
	}
	assert.True(t, found, "upgrade command should be registered")
}

func TestUpgradeCmd_Flags(t *testing.T) {
	var found *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "upgrade" {
			found = cmd
			break
		}
	}
	require.NotNil(t, found)

	checkFlag := found.Flags().Lookup("check")
	assert.NotNil(t, checkFlag, "--check flag should exist")

	forceFlag := found.Flags().Lookup("force")
	assert.NotNil(t, forceFlag, "--force flag should exist")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/cli/... -run TestUpgradeCmd -v`
Expected: FAIL — command not registered

- [ ] **Step 3: Implement upgrade command**

Create `internal/cli/upgrade.go`:

```go
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/updater"
	"github.com/spf13/cobra"
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Check for and apply updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.SetupLoggingDefaults()

		checkOnly, _ := cmd.Flags().GetBool("check")
		force, _ := cmd.Flags().GetBool("force")

		// Load config to get update_repo.
		cfg, err := config.Load(cfgFile)
		if err != nil {
			slog.Warn("config load failed, using default repo", "error", err)
			cfg = &config.Config{}
			cfg.Server.UpdateRepo = "binn/ccproxy"
		}

		repo := cfg.Server.UpdateRepo
		if repo == "" {
			repo = "binn/ccproxy"
		}

		u := updater.New(updater.Config{
			CurrentVersion: Version,
			Repo:           repo,
			CheckInterval:  time.Hour, // unused for CLI
			AutoUpdate:     false,     // unused for CLI
		})

		if Version == "dev" {
			fmt.Fprintln(os.Stderr, "warning: running dev version, upgrade may not work as expected")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Printf("Current version: %s\n", Version)
		fmt.Printf("Checking %s for updates...\n", repo)

		latest, err := u.CheckNow(ctx)
		if err != nil {
			return fmt.Errorf("check for updates: %w", err)
		}

		fmt.Printf("Latest version:  %s\n", latest)

		if latest == Version && !force {
			fmt.Println("Already up to date.")
			return nil
		}

		if checkOnly {
			if latest != Version {
				fmt.Printf("Update available: %s -> %s\n", Version, latest)
			}
			return nil
		}

		fmt.Printf("Upgrading %s -> %s...\n", Version, latest)
		updated, newVer, err := u.Apply(ctx, force)
		if err != nil {
			return fmt.Errorf("apply update: %w", err)
		}
		if updated {
			fmt.Printf("Successfully upgraded to %s\n", newVer)
			fmt.Println("Restart ccproxy to use the new version.")
		} else {
			fmt.Println("No update applied.")
		}
		return nil
	},
}

func init() {
	upgradeCmd.Flags().Bool("check", false, "check only, do not apply")
	upgradeCmd.Flags().Bool("force", false, "force upgrade (allow downgrade)")
	rootCmd.AddCommand(upgradeCmd)
}
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/cli/... -run TestUpgradeCmd -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/upgrade.go internal/cli/upgrade_test.go
git commit -m "feat(cli): add upgrade subcommand"
```

---

### Task 5: Wire Updater into Server, Admin Handler, and Observability

This task combines server wiring, admin handler changes, observability integration, and route wiring into a single atomic change to avoid intermediate states where the code doesn't compile.

**Files:**
- Modify: `internal/server/server.go:23-29` (Server struct)
- Modify: `internal/server/server.go:32-178` (New function — signature, updater creation, route wiring, StartPeriodicLog call)
- Modify: `internal/cli/root.go:45` (pass Version to server.New)
- Modify: `internal/admin/handler.go:22-39` (Handler struct, NewHandler)
- Create: `internal/admin/update_handlers.go`
- Modify: `internal/observe/metrics.go:18-20,87-147` (UpdateStatusProvider, StartPeriodicLog)

- [ ] **Step 1: Update observe.Metrics — add UpdateStatusProvider interface and update StartPeriodicLog**

In `internal/observe/metrics.go`, add after the StateProvider interface (line 20):

```go
// UpdateStatusProvider supplies update state for periodic logging.
type UpdateStatusProvider interface {
	Status() UpdateStatus
}

// UpdateStatus represents the current update state for logging.
type UpdateStatus struct {
	CurrentVersion string
	LatestVersion  string
	LastCheck      time.Time
}
```

Change `StartPeriodicLog` signature (line 87) to:

```go
func (m *Metrics) StartPeriodicLog(ctx context.Context, interval time.Duration, state StateProvider, updateProv UpdateStatusProvider, logger *slog.Logger) {
```

Inside the ticker case, after `logSystemMetrics(logger)` (line 143), add:

```go
if updateProv != nil {
	us := updateProv.Status()
	attrs := []any{
		"current_version", us.CurrentVersion,
	}
	if us.LatestVersion != "" {
		attrs = append(attrs, "latest_version", us.LatestVersion)
	}
	if !us.LastCheck.IsZero() {
		attrs = append(attrs, "last_check", us.LastCheck.Format(time.RFC3339))
	}
	logger.Info("update status", attrs...)
}
```

- [ ] **Step 2: Update admin.Handler — add updater field and accept in NewHandler**

In `internal/admin/handler.go`, add import:

```go
"github.com/binn/ccproxy/internal/updater"
```

Add to Handler struct (after line 27):

```go
updater *updater.Updater
```

Update `NewHandler` (line 31) to accept `*updater.Updater`:

```go
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config, registry *config.AccountRegistry, upd *updater.Updater) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
		registry: registry,
		updater:  upd,
	}
}
```

- [ ] **Step 3: Create update API handlers**

Create `internal/admin/update_handlers.go`:

```go
package admin

import (
	"encoding/json"
	"net/http"

	"github.com/binn/ccproxy/internal/updater"
)

// HandleUpdateStatus returns the current update status.
func (h *Handler) HandleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if h.updater == nil {
		json.NewEncoder(w).Encode(updater.UpdateStatus{})
		return
	}

	json.NewEncoder(w).Encode(h.updater.Status())
}

// HandleUpdateCheck triggers an immediate version check.
func (h *Handler) HandleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.updater == nil {
		http.Error(w, "updater not available", http.StatusServiceUnavailable)
		return
	}

	latest, err := h.updater.CheckNow(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"latest": latest})
}

// HandleUpdateApply triggers an immediate upgrade.
func (h *Handler) HandleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.updater == nil {
		http.Error(w, "updater not available", http.StatusServiceUnavailable)
		return
	}

	updated, newVer, err := h.updater.Apply(r.Context(), false)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"updated":     updated,
		"new_version": newVer,
	})

	if updated {
		go h.updater.Restart()
	}
}
```

- [ ] **Step 4: Update server.go — add updater to Server, wire everything**

In `internal/server/server.go`:

Add imports:
```go
"github.com/binn/ccproxy/internal/updater"
```

Add `updater` field to Server struct (line 28):
```go
updater *updater.Updater
```

Change `New` signature (line 32):
```go
func New(cfg *config.Config, version string) (*Server, error) {
```

**Before** the `StartPeriodicLog` call (line 113), insert updater creation:

```go
// Create auto-updater.
var upd *updater.Updater
checkInterval, _ := time.ParseDuration(cfg.Server.UpdateCheckInterval)
if checkInterval == 0 {
	checkInterval = time.Hour
}
upd = updater.New(updater.Config{
	CurrentVersion: version,
	Repo:           cfg.Server.UpdateRepo,
	CheckInterval:  checkInterval,
	AutoUpdate:     cfg.Server.IsAutoUpdateEnabled(),
})
go upd.Start(ctx)
```

**Replace** the `StartPeriodicLog` call (line 113) with:

```go
// Start periodic metrics logging with update status.
var updateProv observe.UpdateStatusProvider
if upd != nil {
	updateProv = &updateAdapter{upd: upd}
}
observe.Global.StartPeriodicLog(ctx, 5*time.Minute, balancer, updateProv, nil)
```

**Update** admin handler creation (line 127):
```go
adminHandler := admin.NewHandler(balancer, oauthMgr, oauthSessions, cfg, registry, upd)
```

**Add** update API routes after existing admin routes (after line 151):
```go
mux.Handle("/api/update/status", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateStatus))))
mux.Handle("/api/update/check", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateCheck))))
mux.Handle("/api/update/apply", adminRL(adminAuth(http.HandlerFunc(adminHandler.HandleUpdateApply))))
```

**Add** updater to Server return (line 171-177):
```go
return &Server{
	cfg:        cfg,
	httpServer: httpServer,
	oauthMgr:   oauthMgr,
	balancer:   balancer,
	updater:    upd,
	cancel:     cancel,
}, nil
```

**Add** updateAdapter type at the bottom of server.go:

```go
// updateAdapter adapts *updater.Updater to observe.UpdateStatusProvider.
type updateAdapter struct {
	upd *updater.Updater
}

func (a *updateAdapter) Status() observe.UpdateStatus {
	s := a.upd.Status()
	return observe.UpdateStatus{
		CurrentVersion: s.CurrentVersion,
		LatestVersion:  s.LatestVersion,
		LastCheck:      s.LastCheck,
	}
}
```

- [ ] **Step 5: Update cli/root.go to pass Version**

In `internal/cli/root.go`, change line 45:

```go
srv, err := server.New(cfg, Version)
```

- [ ] **Step 6: Run all tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./... -v -race`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add internal/server/server.go internal/cli/root.go internal/admin/handler.go internal/admin/update_handlers.go internal/observe/metrics.go
git commit -m "feat: wire updater into server, admin API, and observability"
```

---

### Task 6: Add tests for admin update endpoints

**Files:**
- Create: `internal/admin/update_handlers_test.go`

- [ ] **Step 1: Write tests**

Create `internal/admin/update_handlers_test.go`:

```go
package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/updater"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleUpdateStatus(t *testing.T) {
	u := updater.New(updater.Config{
		CurrentVersion: "1.0.0",
		Repo:           "binn/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})

	h := &Handler{updater: u}

	req := httptest.NewRequest(http.MethodGet, "/api/update/status", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var status updater.UpdateStatus
	err := json.Unmarshal(w.Body.Bytes(), &status)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", status.CurrentVersion)
	assert.True(t, status.AutoUpdate)
}

func TestHandleUpdateStatus_NoUpdater(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodGet, "/api/update/status", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateStatus(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandleUpdateStatus_MethodNotAllowed(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodPost, "/api/update/status", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateStatus(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleUpdateCheck_NoUpdater(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodPost, "/api/update/check", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateCheck(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleUpdateApply_NoUpdater(t *testing.T) {
	h := &Handler{updater: nil}

	req := httptest.NewRequest(http.MethodPost, "/api/update/apply", nil)
	w := httptest.NewRecorder()
	h.HandleUpdateApply(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
```

- [ ] **Step 2: Run tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/admin/... -run TestHandleUpdate -v -race`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add internal/admin/update_handlers_test.go
git commit -m "test(admin): add update endpoint tests"
```

---

## Chunk 3: Release Workflow & Docs

### Task 7: Add GoReleaser config and GitHub Actions workflow

**Files:**
- Create: `.goreleaser.yml`
- Create: `.github/workflows/release.yml`
- Modify: `Makefile`

- [ ] **Step 1: Create GoReleaser config**

Create `.goreleaser.yml`:

```yaml
version: 2

builds:
  - id: ccproxy
    main: ./cmd/ccproxy
    binary: ccproxy
    env:
      - CGO_ENABLED=0
    goos:
      - linux
    goarch:
      - amd64
      - arm64
    ldflags:
      - -s -w -X github.com/binn/ccproxy/internal/cli.Version={{.Version}}

archives:
  - id: ccproxy
    builds:
      - ccproxy
    name_template: "ccproxy_{{ .Version }}_{{ .Os }}_{{ .Arch }}"
    format: tar.gz

checksum:
  name_template: "checksums.txt"
  algorithm: sha256

release:
  github:
    owner: binn
    name: ccproxy
  draft: false
  prerelease: auto
```

- [ ] **Step 2: Create release workflow**

Run: `mkdir -p /Users/binn/ZedProjects/token-run-workspace/ccproxy/.github/workflows`

Create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - "v*"

permissions:
  contents: write

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version: "1.25"

      - uses: goreleaser/goreleaser-action@v6
        with:
          version: "~> v2"
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 3: Add release target to Makefile**

Add to `.PHONY` line: `release`

Add after `docker-push` target:

```makefile
release:
	@if [ -z "$(VERSION)" ] || [ "$(VERSION)" = "dev" ]; then echo "Usage: make release VERSION=x.y.z"; exit 1; fi
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)
```

- [ ] **Step 4: Commit**

```bash
git add .goreleaser.yml .github/workflows/release.yml Makefile
git commit -m "ci: add GoReleaser config and release workflow"
```

---

### Task 8: Update documentation

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update CLAUDE.md**

Add to the "关键目录" section (in the `internal/` tree):

```
  updater/          OTA 自动升级引擎（GitHub Releases + go-selfupdate）
```

Add to "重要模式" section a new subsection:

```markdown
### 自动升级

- `internal/updater/` 使用 `go-selfupdate` 检查 GitHub Releases 并自动替换二进制
- 后台定期检查（默认 1 小时），发现新版本后下载、校验 SHA256、原子替换、发送 SIGTERM 触发重启
- Docker 环境自动禁用（检测 `/.dockerenv`）
- `dev` 版本跳过后台检查
- CLI: `ccproxy upgrade [--check] [--force]`
- Admin API: `GET /api/update/status`, `POST /api/update/check`, `POST /api/update/apply`
```

Add to "构建命令" section:

```bash
make release VERSION=1.0.0  # 创建 git tag 并推送，触发 CI 发布
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add auto-update documentation to CLAUDE.md"
```

---

### Task 9: Final integration test

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./... -v -race`
Expected: ALL PASS

- [ ] **Step 2: Build and verify version output**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && VERSION=1.0.0-test make build && ./bin/ccproxy version`
Expected: `ccproxy 1.0.0-test`

- [ ] **Step 3: Verify upgrade command exists**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && ./bin/ccproxy upgrade --check`
Expected: Should attempt to check GitHub (may fail if no releases exist yet, but command should not panic)

- [ ] **Step 4: Verify help output**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && ./bin/ccproxy --help`
Expected: Should list `upgrade` and `version` subcommands
