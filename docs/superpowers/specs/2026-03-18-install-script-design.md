# Install Script Design

## Overview

Add a `curl | sh` install script for ccproxy. The script downloads the correct binary from GitHub Releases, verifies its SHA256 checksum, installs it, and optionally sets up a systemd service with a dedicated `ccproxy` user.

Also fix all GitHub repository references from `binn/ccproxy` to `shuzuan-org/ccproxy`.

## Install Script

### File

`install.sh` in repository root. Distributed via:

```bash
curl -fsSL https://raw.githubusercontent.com/shuzuan-org/ccproxy/master/install.sh | sh
```

### Usage

```
install.sh [OPTIONS]

Options:
  --version VERSION     Install specific version (default: latest release)
  --install-dir DIR     Binary install path (default: /usr/local/bin)
  --with-systemd        Create systemd service, user, and directories
  --dry-run             Print actions without executing
  --help                Show usage
```

### Flow

1. Parse arguments
2. Check: must be Linux. Root is required if `--install-dir` needs elevated privileges (default `/usr/local/bin`) or `--with-systemd` is used
3. Detect architecture: `uname -m` → `amd64` (x86_64) or `arm64` (aarch64)
4. Resolve version: if `--version` not set, query GitHub API for latest release tag (e.g. `v1.2.3`). Strip the `v` prefix to get the version number (`1.2.3`) used in asset filenames, since GoReleaser's `{{ .Version }}` produces names without the `v` prefix
5. Download `ccproxy_{version}_linux_{arch}.tar.gz` + `checksums.txt` to temp directory
6. Verify SHA256 checksum
7. Extract archive, install binary to `--install-dir` with mode 0755
8. If `--with-systemd`:
   a. Create system user `ccproxy` (`useradd --system --no-create-home --shell /usr/sbin/nologin`)
   b. Create directories `/etc/ccproxy` (0755) and `/var/lib/ccproxy` (0700, owned by ccproxy)
   c. Write systemd unit file to `/etc/systemd/system/ccproxy.service`
   d. `systemctl daemon-reload && systemctl enable ccproxy`
   e. Print instructions to start the service
9. Clean up temp directory
10. Print install summary with version and path

**No config file is created.** ccproxy auto-generates `config.toml` with secure credentials on first startup (admin password + API key printed to log). The systemd unit points to `-c /etc/ccproxy/config.toml`; ccproxy creates this file itself.

### Systemd Unit

```ini
[Unit]
Description=ccproxy - Claude API Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ccproxy
Group=ccproxy
ExecStart=INSTALL_DIR/ccproxy -c /etc/ccproxy/config.toml  # INSTALL_DIR defaults to /usr/local/bin
WorkingDirectory=/var/lib/ccproxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

`Restart=always` works with OTA auto-upgrade: after upgrade, ccproxy sends SIGTERM to self → systemd restarts the new binary.

`ExecStart` path is adjusted if `--install-dir` differs from default.

### Compatibility

- **Shell:** Pure POSIX sh (no bashism). Works on Ubuntu, CentOS, Debian, Alpine.
- **Download:** `curl` preferred, fallback to `wget`
- **Checksum:** `sha256sum` preferred, fallback to `shasum -a 256`
- **Root:** Required when `--install-dir` needs elevated privileges or `--with-systemd` is used. Non-root install to user-writable directories (e.g. `$HOME/bin`) is supported without `--with-systemd`
- **systemd check:** `--with-systemd` verifies that `systemctl` exists before proceeding; exits with error if not found (covers Alpine/OpenRC environments)

### Error Handling

- Non-Linux OS → exit with error message
- Unsupported architecture → exit with error message
- Download failure → exit with error, clean up temp files
- Checksum mismatch → exit with error, clean up temp files
- User already exists (re-install) → skip user creation silently
- Service file already exists → overwrite (upgrade scenario)
- `--dry-run` → print all commands that would execute, exit 0

## Repository Reference Fix

All references to `binn/ccproxy` as the GitHub repository (not the Go module path) are updated to `shuzuan-org/ccproxy`:

| File | Field | Old | New |
|------|-------|-----|-----|
| `internal/config/config.go` | `UpdateRepo` default in `applyDefaults()` | `binn/ccproxy` | `shuzuan-org/ccproxy` |
| `internal/cli/upgrade.go` | two fallback repo values | `binn/ccproxy` | `shuzuan-org/ccproxy` |
| `.goreleaser.yml` | `release.github.owner` | `binn` | `shuzuan-org` |
| `config.toml.example` | comment for `update_repo` | `binn/ccproxy` | `shuzuan-org/ccproxy` |
| `internal/config/config_test.go` | test assertion for default repo | `binn/ccproxy` | `shuzuan-org/ccproxy` |
| `internal/updater/updater_test.go` | test `Repo` field values | `binn/ccproxy` | `shuzuan-org/ccproxy` |
| `internal/admin/update_handlers_test.go` | test `Repo` field value | `binn/ccproxy` | `shuzuan-org/ccproxy` |

**Note:** The Go module path `github.com/binn/ccproxy` is NOT changed — that is a separate concern (Go module path ≠ GitHub hosting location).
