# Update Channel Design

**Date:** 2026-03-30
**Status:** Approved
**Scope:** `internal/updater`, `internal/config`, `internal/admin`

## Overview

Add a `stable` / `beta` release channel to the auto-upgrade system. `stable` (default) tracks GitHub formal releases only. `beta` also considers pre-releases (`prerelease: true` in GitHub Releases).

## Configuration

New field in `config.toml` under `[server]`:

```toml
update_channel = "stable"   # "stable" (default) or "beta"
```

**`ServerConfig` change (`internal/config/config.go`):**
```go
UpdateChannel string `toml:"update_channel"`
```

- `applyDefaults`: set to `"stable"` when empty
- `validate`: reject any value other than `"stable"` or `"beta"`

**`updater.Config` change (`internal/updater/updater.go`):**
```go
Channel string   // "stable" | "beta"
```

`server.go` passes `cfg.Server.UpdateChannel` when constructing `updater.New`.

## Updater Logic

`findLatest` branches on `Channel`:

### stable (unchanged)
```
upd.DetectLatest(ctx, slug)
```
`go-selfupdate` skips pre-releases by default. No change.

### beta (new path)
1. Call `GET https://api.github.com/repos/{owner}/{repo}/releases` via `net/http`.
   GitHub returns releases in reverse-chronological order (newest first), including pre-releases.
2. Take the first entry. Extract the version from `tag_name` (strip leading `v`).
3. Call `upd.DetectVersion(ctx, slug, version)` — go-selfupdate's exact-version lookup, which runs the same checksums.txt validation and atomic replacement as the stable path.
4. Return `*selfupdate.Release`. Downstream `Apply` is identical for both channels.

Version comparison (`LessOrEqual` / `LessThan`) is unchanged for both paths.

### Testability

A private `releaseSource` interface wraps the GitHub API call:

```go
type releaseSource interface {
    latestRelease(ctx context.Context, owner, repo string) (tagName string, err error)
}
```

- `httpReleaseSource`: production implementation using `net/http`
- Mock implementation injected in tests

## UpdateStatus

`UpdateStatus` gains a `Channel` field:

```go
type UpdateStatus struct {
    CurrentVersion string    `json:"current_version"`
    LatestVersion  string    `json:"latest_version"`
    LastCheck      time.Time `json:"last_check"`
    AutoUpdate     bool      `json:"auto_update"`
    Channel        string    `json:"channel"`   // new
    Checking       bool      `json:"checking"`
    Updating       bool      `json:"updating"`
}
```

`Status()` populates it from `cfg.Channel`.

## Testing

| Test | Channel | Scenario | Expected |
|------|---------|----------|----------|
| existing | stable | pre-release exists | skipped |
| new | beta | latest is pre-release | selected |
| new | beta | latest is formal release | selected |
| new | beta | releases list empty | nil, nil (no update) |
| new | beta | GitHub API error | error propagated |
| new | config | `update_channel = "nightly"` | validation error |

## Files Changed

| File | Change |
|------|--------|
| `internal/config/config.go` | Add `UpdateChannel` field, default, validation |
| `internal/updater/updater.go` | Add `Channel` to `Config`, `releaseSource` interface, beta path in `findLatest`, `Channel` in `UpdateStatus` / `Status()` |
| `internal/updater/updater_test.go` | New test cases for beta channel |
| `internal/server/server.go` | Pass `UpdateChannel` to `updater.New` |
| `config.toml.example` | Document `update_channel` |
