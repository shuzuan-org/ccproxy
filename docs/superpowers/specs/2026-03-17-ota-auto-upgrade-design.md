# OTA Auto-Upgrade Design

## Overview

Add self-update capability to ccproxy: background version checking against GitHub Releases, automatic binary replacement, and graceful restart. Uses [creativeprojects/go-selfupdate](https://github.com/creativeprojects/go-selfupdate) library.

**Target deployment:** standalone Linux binary with systemd (or similar) process manager. Auto-update is automatically disabled inside Docker containers (detected via `/.dockerenv`).

## Module Structure

```
internal/updater/
  updater.go      — Updater struct, Start/Stop/CheckNow methods
  github.go       — go-selfupdate GitHub source configuration
  config.go       — config struct and defaults
```

## Configuration

New fields under `[server]` in `config.toml`:

```toml
[server]
auto_update = true            # enable background auto-upgrade (default: true)
update_check_interval = "1h"  # check interval (default: 1h, minimum: 5m)
update_repo = "binn/ccproxy"  # GitHub repository (default)
```

**Go struct fields** (added to `ServerConfig` in `internal/config/config.go`):

```go
AutoUpdate            bool   `toml:"auto_update"`
UpdateCheckInterval   string `toml:"update_check_interval"`  // parsed to time.Duration manually
UpdateRepo            string `toml:"update_repo"`
```

- `UpdateCheckInterval` stored as `string` in config, parsed via `time.ParseDuration()` at load time
- Validation: minimum 5 minutes, maximum 24 hours; invalid values fall back to default `"1h"`
- Defaults applied in `config.Load()` alongside existing defaults

## Version Check

1. On startup, if `auto_update = true` AND `Version != "dev"` AND not in Docker, launch background goroutine
2. Every `update_check_interval`, call GitHub Releases API for latest release
3. Compare `cli.Version` vs remote tag using semver — upgrade only if remote is newer
4. `dev` version skips background check (dev environment should not auto-upgrade)

## Lifecycle & Wiring

The `Updater` is created and owned by `server.Server`:

1. **Creation:** `server.New()` creates `updater.New(cfg, logger)` and stores it on the `Server` struct
2. **Start:** `server.Start()` calls `updater.Start(ctx)` with the server's context — background goroutine respects this context for cancellation
3. **Stop:** `s.cancel()` during shutdown propagates to the updater's goroutine via context
4. **Admin access:** `admin.Handler` receives a pointer to `Updater` for API route handling

## Upgrade Flow

1. **Download** — `go-selfupdate` auto-matches asset by `runtime.GOOS` + `runtime.GOARCH`, downloads to temp file
2. **Verify** — SHA256 checksum validation against `checksums.txt` asset
3. **Replace** — atomic rename: write temp file → preserve original permissions → rename over existing binary
4. **Restart** — log `"upgrade successful, restarting"` with old/new version → send `SIGTERM` to self → rely on systemd `Restart=always` to bring up new process

**In-flight request handling:** SIGTERM triggers the existing graceful shutdown with 10-second drain timeout. Active SSE streams will be terminated after the timeout. This is an accepted trade-off — clients (Claude Code CLI) already handle reconnection.

### Failure Handling

- Download failure / checksum mismatch → log warning, keep current version, retry next cycle
- Replace failure (permissions etc.) → log error, keep current version running
- No rollback mechanism (standard practice for self-updating binaries; user intervenes manually if new version fails to start)

## CLI Command

```
ccproxy upgrade          # check and upgrade immediately
ccproxy upgrade --check  # check only, print result
ccproxy upgrade --force  # allow downgrade or re-install same version
```

- Works regardless of `auto_update` setting
- Reads `config.toml` (via `--config` flag, same as root command) to respect `update_repo` override
- Outputs current version, latest version, upgrade result
- `dev` version shows warning but still allows execution
- `--force` bypasses semver comparison (allows downgrade/reinstall)

## Admin Integration

### UI

Version info section on existing admin dashboard:
- Display: current version, latest available version, last check time
- Buttons: "Check Now", "Upgrade Now"
- Status feedback: checking / downloading / upgrading / up-to-date

### API Routes

Served by `admin.Handler` (which receives `*updater.Updater`), protected by existing `adminRL(adminAuth(...))` middleware chain:

```
GET  /api/update/status   — current version, latest version, last check time, auto_update status
POST /api/update/check    — trigger immediate check
POST /api/update/apply    — trigger immediate upgrade
```

### Observability

The `Updater` exposes a `Status() UpdateStatus` method. The periodic log reporter in `internal/observe/` calls this method directly (no StateProvider interface change needed) and appends update info to its log output:

```json
{"update": {"current": "1.0.0", "latest": "1.2.0", "last_check": "2026-03-17T10:00:00Z"}}
```

## Security

- **HTTPS only** — all GitHub API calls and asset downloads over HTTPS
- **Checksum verification** — SHA256 via `go-selfupdate`
- **No downgrade** — semver comparison ensures only upgrades; CLI `--force` flag explicitly overrides this
- **Rate limit safe** — GitHub unauthenticated API allows 60 req/h; 1h default check interval is well within limits
- **Docker safe** — auto-update disabled when `/.dockerenv` exists

## GitHub Releases Asset Convention

```
ccproxy_{version}_linux_amd64.tar.gz
ccproxy_{version}_linux_arm64.tar.gz
ccproxy_{version}_checksums.txt
```

## Release Workflow

New `.github/workflows/release.yml`, using [GoReleaser](https://goreleaser.com/) for asset generation (natively compatible with `go-selfupdate` naming conventions):

1. Triggered by `v*` tag push
2. GoReleaser cross-compiles: `linux/amd64`, `linux/arm64` (CGO_ENABLED=0)
3. Packages as `ccproxy_{version}_{os}_{arch}.tar.gz`
4. Generates `checksums.txt` (SHA256)
5. Creates GitHub Release and uploads all assets

### Makefile Addition

```makefile
make release VERSION=1.2.0   # create git tag and push, triggers CI release
```

## Dependencies

- `github.com/creativeprojects/go-selfupdate` — self-update library with GitHub Releases support
- GoReleaser — CI release tool (GitHub Actions only, not a Go dependency)
