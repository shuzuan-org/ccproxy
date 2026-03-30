# Update Channel (stable/beta) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `update_channel = "stable" | "beta"` to `config.toml`; beta channel passes `Prerelease: true` to go-selfupdate so pre-releases are included in upgrade checks.

**Architecture:** `go-selfupdate` v1.5.2 natively supports `Config.Prerelease bool`; setting it to `true` makes `findReleaseAndAsset` include GitHub pre-releases. The channel flag flows: `config.toml` → `ServerConfig.UpdateChannel` → `updater.Config.Channel` → `selfupdate.Config{Prerelease: true}` inside `findLatest`. `UpdateStatus` exposes the channel for admin dashboard visibility.

**Tech Stack:** Go 1.25, `github.com/creativeprojects/go-selfupdate v1.5.2`, `github.com/BurntSushi/toml`

---

## File Map

| File | Change |
|------|--------|
| `internal/config/config.go` | Add `UpdateChannel string` to `ServerConfig`; default + validation |
| `internal/config/config_test.go` | Tests for default and validation |
| `internal/updater/updater.go` | Add `Channel` to `Config` + `UpdateStatus`; update `Status()` + `findLatest` |
| `internal/updater/updater_test.go` | Tests for channel in Status |
| `internal/server/server.go` | Pass `Channel` when constructing `updater.New` |
| `config.toml.example` | Document `update_channel` field |

---

### Task 1: Config — add UpdateChannel field with default and validation

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests**

Open `internal/config/config_test.go` and add at the end of the file:

```go
func TestApplyDefaults_UpdateChannel(t *testing.T) {
	cfg := &Config{}
	cfg.applyDefaults()
	if cfg.Server.UpdateChannel != "stable" {
		t.Errorf("expected default UpdateChannel \"stable\", got %q", cfg.Server.UpdateChannel)
	}
}

func TestApplyDefaults_UpdateChannel_PreservesExisting(t *testing.T) {
	cfg := &Config{Server: ServerConfig{UpdateChannel: "beta"}}
	cfg.applyDefaults()
	if cfg.Server.UpdateChannel != "beta" {
		t.Errorf("expected UpdateChannel \"beta\" preserved, got %q", cfg.Server.UpdateChannel)
	}
}

// baseValidConfig returns a minimal valid Config for Validate() tests.
// Uses a helper to avoid duplicating the struct literal across tests.
func baseValidConfig() *Config {
	return &Config{
		Server: ServerConfig{
			AdminPassword:       "secret",
			UpdateCheckInterval: "1h",
			UpdateChannel:       "stable",
		},
		APIKeys: []APIKeyConfig{
			{Key: "sk-test", Name: "test", Enabled: true},
		},
	}
}

func TestValidate_UpdateChannel_Invalid(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Server.UpdateChannel = "nightly"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid update_channel, got nil")
	}
	if !strings.Contains(err.Error(), "update_channel") {
		t.Errorf("error %q should mention update_channel", err.Error())
	}
}

func TestValidate_UpdateChannel_Beta(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Server.UpdateChannel = "beta"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error for channel \"beta\", got %v", err)
	}
}

func TestValidate_UpdateChannel_Stable(t *testing.T) {
	cfg := baseValidConfig()
	cfg.Server.UpdateChannel = "stable"
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error for channel \"stable\", got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/config/... -run "TestApplyDefaults_UpdateChannel|TestValidate_UpdateChannel" -v
```

Expected: FAIL — `cfg.Server.UpdateChannel` field does not exist yet.

- [ ] **Step 3: Add UpdateChannel to ServerConfig**

In `internal/config/config.go`, add the field after `UpdateAPIURL`:

```go
UpdateChannel       string `toml:"update_channel"`            // "stable" (default) or "beta"
```

- [ ] **Step 4: Add default in applyDefaults**

In the `applyDefaults` function, after the `if cfg.Server.UpdateRepo == ""` block:

```go
if cfg.Server.UpdateChannel == "" {
    cfg.Server.UpdateChannel = "stable"
}
```

- [ ] **Step 5: Add validation in Validate**

In the `Validate` function, after the `update_check_interval` validation block:

```go
if cfg.Server.UpdateChannel != "stable" && cfg.Server.UpdateChannel != "beta" {
    errs = append(errs, fmt.Errorf("update_channel must be \"stable\" or \"beta\", got %q", cfg.Server.UpdateChannel))
}
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
go test ./internal/config/... -run "TestApplyDefaults_UpdateChannel|TestValidate_UpdateChannel" -v
```

Expected: all 5 tests PASS.

- [ ] **Step 7: Run full config tests to check no regressions**

```bash
go test ./internal/config/... -race -count=1
```

Expected: ok

- [ ] **Step 8: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add update_channel field (stable/beta)"
```

---

### Task 2: Updater — Channel in Config, UpdateStatus, and findLatest

**Files:**
- Modify: `internal/updater/updater.go`
- Test: `internal/updater/updater_test.go`

- [ ] **Step 1: Write the failing tests**

Open `internal/updater/updater_test.go` and add at the end:

```go
func TestStatus_ChannelDefault(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
	})
	assert.Equal(t, "", u.Status().Channel) // empty when not set
}

func TestStatus_ChannelStable(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
		Channel:        "stable",
	})
	assert.Equal(t, "stable", u.Status().Channel)
}

func TestStatus_ChannelBeta(t *testing.T) {
	t.Parallel()
	u := New(Config{
		CurrentVersion: "1.0.0",
		Repo:           "shuzuan-org/ccproxy",
		CheckInterval:  time.Hour,
		AutoUpdate:     true,
		Channel:        "beta",
	})
	assert.Equal(t, "beta", u.Status().Channel)
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/updater/... -run "TestStatus_Channel" -v
```

Expected: FAIL — `Config.Channel` field does not exist yet.

- [ ] **Step 3: Add Channel to updater.Config**

In `internal/updater/updater.go`, in the `Config` struct, add after `APIURL`:

```go
Channel string // "stable" | "beta"; empty defaults to stable behaviour
```

- [ ] **Step 4: Add Channel to UpdateStatus**

In the `UpdateStatus` struct, add after `AutoUpdate`:

```go
Channel string `json:"channel"`
```

- [ ] **Step 5: Return Channel from Status()**

In the `Status()` method, add `Channel` to the returned struct:

```go
func (u *Updater) Status() UpdateStatus {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return UpdateStatus{
		CurrentVersion: u.cfg.CurrentVersion,
		LatestVersion:  u.latest,
		LastCheck:      u.lastCheck,
		AutoUpdate:     u.cfg.AutoUpdate,
		Channel:        u.cfg.Channel,
		Checking:       u.checking,
		Updating:       u.updating,
	}
}
```

- [ ] **Step 6: Set Prerelease flag in findLatest**

In `findLatest`, find the `selfupdate.NewUpdater` call:

```go
upd, err := selfupdate.NewUpdater(selfupdate.Config{
    Source:    source,
    Validator: &selfupdate.ChecksumValidator{UniqueFilename: "checksums.txt"},
})
```

Replace with:

```go
upd, err := selfupdate.NewUpdater(selfupdate.Config{
    Source:     source,
    Validator:  &selfupdate.ChecksumValidator{UniqueFilename: "checksums.txt"},
    Prerelease: u.cfg.Channel == "beta",
})
```

- [ ] **Step 7: Run tests to confirm they pass**

```bash
go test ./internal/updater/... -run "TestStatus_Channel" -v
```

Expected: all 3 tests PASS.

- [ ] **Step 8: Run full updater tests**

```bash
go test ./internal/updater/... -race -count=1
```

Expected: ok

- [ ] **Step 9: Commit**

```bash
git add internal/updater/updater.go internal/updater/updater_test.go
git commit -m "feat(updater): add Channel to Config and UpdateStatus, set Prerelease for beta channel"
```

---

### Task 3: Wire Channel through server.go and document in config.toml.example

**Files:**
- Modify: `internal/server/server.go`
- Modify: `config.toml.example`

- [ ] **Step 1: Pass Channel in server.go**

In `internal/server/server.go`, find the `updater.New` call:

```go
upd := updater.New(updater.Config{
    CurrentVersion: version,
    Repo:           cfg.Server.UpdateRepo,
    CheckInterval:  checkInterval,
    AutoUpdate:     cfg.Server.IsAutoUpdateEnabled(),
    APIURL:         cfg.Server.UpdateAPIURL,
})
```

Replace with:

```go
upd := updater.New(updater.Config{
    CurrentVersion: version,
    Repo:           cfg.Server.UpdateRepo,
    CheckInterval:  checkInterval,
    AutoUpdate:     cfg.Server.IsAutoUpdateEnabled(),
    APIURL:         cfg.Server.UpdateAPIURL,
    Channel:        cfg.Server.UpdateChannel,
})
```

- [ ] **Step 2: Document in config.toml.example**

Open `config.toml.example`, find the `[server]` section with update-related fields and add the new field. Find the line containing `update_api_url` and add after it:

```toml
# update_channel = "stable"   # Release channel: "stable" (default) or "beta" (includes pre-releases)
```

- [ ] **Step 3: Build to verify no compile errors**

```bash
make build
```

Expected: builds cleanly.

- [ ] **Step 4: Run full test suite**

```bash
go test ./... -race -count=1
```

Expected: all packages pass.

- [ ] **Step 5: Commit**

```bash
git add internal/server/server.go config.toml.example
git commit -m "feat(server): wire update_channel through to updater"
```

---

## Self-Review Checklist

- [x] Spec coverage: config field + default + validation ✓ | updater Channel field ✓ | UpdateStatus.Channel ✓ | findLatest Prerelease flag ✓ | server.go wiring ✓ | config.toml.example ✓
- [x] No placeholders: all steps have complete code
- [x] Type consistency: `Channel string` used consistently across Config structs; `selfupdate.Config.Prerelease` is a `bool` set via `u.cfg.Channel == "beta"` ✓
- [x] Test for `validConfig()` helper: config_test.go does NOT have this helper — plan uses `baseValidConfig()` defined inline in the new tests instead ✓
