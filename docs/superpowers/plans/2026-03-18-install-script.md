# Install Script Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `curl | sh` install script for ccproxy with optional systemd setup, and fix GitHub repo references from `binn/ccproxy` to `shuzuan-org/ccproxy`.

**Architecture:** Single POSIX shell script (`install.sh`) that downloads from GitHub Releases, verifies SHA256, installs binary, and optionally creates systemd service. Repo reference fix is a straightforward find-and-replace across source, config, and test files.

**Tech Stack:** POSIX sh, GitHub Releases API, GoReleaser

**Spec:** `docs/superpowers/specs/2026-03-18-install-script-design.md`

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `install.sh` | Install script (POSIX sh) |
| Modify | `internal/config/config.go:156` | Fix default UpdateRepo |
| Modify | `internal/cli/upgrade.go:29,34` | Fix fallback repo values |
| Modify | `.goreleaser.yml:30` | Fix release.github.owner |
| Modify | `config.toml.example:12` | Fix comment |
| Modify | `internal/config/config_test.go:435` | Fix test assertion |
| Modify | `internal/updater/updater_test.go:14,30,42,56,81,106` | Fix test Repo fields |
| Modify | `internal/admin/update_handlers_test.go:18` | Fix test Repo field |

---

## Chunk 1: Repository Reference Fix

### Task 1: Fix GitHub repo references

All occurrences of `"binn/ccproxy"` as GitHub repo (NOT Go module path) must change to `"shuzuan-org/ccproxy"`.

**Files:**
- Modify: `internal/config/config.go:156`
- Modify: `internal/cli/upgrade.go:29,34`
- Modify: `.goreleaser.yml:30`
- Modify: `config.toml.example:12`
- Modify: `internal/config/config_test.go:435`
- Modify: `internal/updater/updater_test.go:14,30,42,56,81,106`
- Modify: `internal/admin/update_handlers_test.go:18`

- [ ] **Step 1: Fix source files**

In `internal/config/config.go`, line 156, change:
```go
cfg.Server.UpdateRepo = "binn/ccproxy"
```
To:
```go
cfg.Server.UpdateRepo = "shuzuan-org/ccproxy"
```

In `internal/cli/upgrade.go`, line 29, change:
```go
cfg.Server.UpdateRepo = "binn/ccproxy"
```
To:
```go
cfg.Server.UpdateRepo = "shuzuan-org/ccproxy"
```

In `internal/cli/upgrade.go`, line 34, change:
```go
repo = "binn/ccproxy"
```
To:
```go
repo = "shuzuan-org/ccproxy"
```

- [ ] **Step 2: Fix GoReleaser and config example**

In `.goreleaser.yml`, line 30, change:
```yaml
    owner: binn
```
To:
```yaml
    owner: shuzuan-org
```

In `config.toml.example`, line 12, change:
```toml
# update_repo = "binn/ccproxy" # GitHub owner/repo for update source
```
To:
```toml
# update_repo = "shuzuan-org/ccproxy" # GitHub owner/repo for update source
```

- [ ] **Step 3: Fix test files**

In `internal/config/config_test.go`, lines 435-436, change:
```go
if cfg.Server.UpdateRepo != "binn/ccproxy" {
    t.Errorf("UpdateRepo default = %q, want binn/ccproxy", cfg.Server.UpdateRepo)
```
To:
```go
if cfg.Server.UpdateRepo != "shuzuan-org/ccproxy" {
    t.Errorf("UpdateRepo default = %q, want shuzuan-org/ccproxy", cfg.Server.UpdateRepo)
```

In `internal/updater/updater_test.go`, replace ALL 6 occurrences (lines 14, 30, 42, 56, 81, 106):
```go
Repo:           "binn/ccproxy",
```
With:
```go
Repo:           "shuzuan-org/ccproxy",
```

In `internal/admin/update_handlers_test.go`, line 18:
```go
Repo:           "binn/ccproxy",
```
With:
```go
Repo:           "shuzuan-org/ccproxy",
```

- [ ] **Step 4: Run tests**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./internal/config/... ./internal/cli/... ./internal/updater/... ./internal/admin/... -race -count=1`
Expected: ALL PASS (except the 3 pre-existing config test failures unrelated to this change)

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/cli/upgrade.go .goreleaser.yml config.toml.example internal/config/config_test.go internal/updater/updater_test.go internal/admin/update_handlers_test.go
git commit -m "fix: update GitHub repo references from binn/ccproxy to shuzuan-org/ccproxy"
```

---

## Chunk 2: Install Script

### Task 2: Create install.sh

**Files:**
- Create: `install.sh`

- [ ] **Step 1: Create the install script**

Create `install.sh` with the following content:

```sh
#!/bin/sh
set -e

# ccproxy install script
# Usage: curl -fsSL https://raw.githubusercontent.com/shuzuan-org/ccproxy/master/install.sh | sh
#   or:  curl -fsSL ... | sh -s -- --with-systemd --version 1.0.0

REPO="shuzuan-org/ccproxy"
INSTALL_DIR="/usr/local/bin"
WITH_SYSTEMD=false
DRY_RUN=false
VERSION=""

# ---- helpers ----

info() { printf '\033[1;32m%s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m%s\033[0m\n' "$*" >&2; }
err()  { printf '\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

need_cmd() {
    if ! command -v "$1" > /dev/null 2>&1; then
        err "required command not found: $1"
    fi
}

# Download a URL to a file. Tries curl first, then wget.
download() {
    url="$1"
    dest="$2"
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL "$url" -o "$dest"
    elif command -v wget > /dev/null 2>&1; then
        wget -q "$url" -O "$dest"
    else
        err "curl or wget is required"
    fi
}

# Run a command, or print it if --dry-run.
run() {
    if [ "$DRY_RUN" = true ]; then
        info "[dry-run] $*"
    else
        "$@"
    fi
}

# ---- argument parsing ----

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --with-systemd)
            WITH_SYSTEMD=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            cat <<'USAGE'
ccproxy installer

Usage: install.sh [OPTIONS]

Options:
  --version VERSION     Install specific version (default: latest)
  --install-dir DIR     Binary install path (default: /usr/local/bin)
  --with-systemd        Create systemd service, user, and directories
  --dry-run             Print actions without executing
  --help                Show this help
USAGE
            exit 0
            ;;
        *)
            err "unknown option: $1 (try --help)"
            ;;
    esac
done

# ---- pre-flight checks ----

OS=$(uname -s)
if [ "$OS" != "Linux" ]; then
    err "this installer only supports Linux (detected: $OS)"
fi

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) err "unsupported architecture: $ARCH (supported: x86_64, aarch64)" ;;
esac

# Check root when needed.
if [ "$(id -u)" -ne 0 ]; then
    # Check if install dir is writable.
    if [ ! -w "$(dirname "$INSTALL_DIR")" ] && [ ! -w "$INSTALL_DIR" ]; then
        err "cannot write to $INSTALL_DIR — run as root or use --install-dir"
    fi
    if [ "$WITH_SYSTEMD" = true ]; then
        err "--with-systemd requires root"
    fi
fi

if [ "$WITH_SYSTEMD" = true ]; then
    if ! command -v systemctl > /dev/null 2>&1; then
        err "--with-systemd requires systemd (systemctl not found)"
    fi
fi

# ---- resolve version ----

if [ -z "$VERSION" ]; then
    info "Fetching latest release..."
    if command -v curl > /dev/null 2>&1; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    elif command -v wget > /dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    else
        err "curl or wget is required"
    fi
    if [ -z "$VERSION" ]; then
        err "failed to fetch latest version from GitHub"
    fi
fi

# Strip v prefix for asset filenames (GoReleaser uses version without v).
VERSION_NUM="${VERSION#v}"
info "Installing ccproxy ${VERSION_NUM} (${ARCH})"

# ---- download and verify ----

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

ARCHIVE="ccproxy_${VERSION_NUM}_linux_${ARCH}.tar.gz"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ARCHIVE}"
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${VERSION}/checksums.txt"

info "Downloading ${ARCHIVE}..."
download "$DOWNLOAD_URL" "${TMPDIR}/${ARCHIVE}"

info "Downloading checksums.txt..."
download "$CHECKSUMS_URL" "${TMPDIR}/checksums.txt"

info "Verifying checksum..."
EXPECTED=$(grep "${ARCHIVE}" "${TMPDIR}/checksums.txt" | awk '{print $1}')
if [ -z "$EXPECTED" ]; then
    err "archive not found in checksums.txt"
fi

if command -v sha256sum > /dev/null 2>&1; then
    ACTUAL=$(sha256sum "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')
elif command -v shasum > /dev/null 2>&1; then
    ACTUAL=$(shasum -a 256 "${TMPDIR}/${ARCHIVE}" | awk '{print $1}')
else
    err "sha256sum or shasum is required for checksum verification"
fi

if [ "$EXPECTED" != "$ACTUAL" ]; then
    err "checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}"
fi
info "Checksum verified."

# ---- install binary ----

info "Extracting to ${INSTALL_DIR}..."
tar -xzf "${TMPDIR}/${ARCHIVE}" -C "${TMPDIR}"

run install -m 0755 "${TMPDIR}/ccproxy" "${INSTALL_DIR}/ccproxy"

info "Installed: ${INSTALL_DIR}/ccproxy"

# ---- systemd setup (optional) ----

if [ "$WITH_SYSTEMD" = true ]; then
    info "Setting up systemd service..."

    # Create system user if not exists.
    if ! id ccproxy > /dev/null 2>&1; then
        run useradd --system --no-create-home --shell /usr/sbin/nologin ccproxy
        info "Created system user: ccproxy"
    else
        info "System user ccproxy already exists, skipping."
    fi

    # Create directories.
    run mkdir -p /etc/ccproxy
    run mkdir -p /var/lib/ccproxy
    run chown ccproxy:ccproxy /var/lib/ccproxy
    run chmod 0700 /var/lib/ccproxy

    # Write systemd unit file (not guarded by dry-run: writing to /tmp is harmless).
    cat > /tmp/ccproxy.service <<UNIT
[Unit]
Description=ccproxy - Claude API Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ccproxy
Group=ccproxy
ExecStart=${INSTALL_DIR}/ccproxy -c /etc/ccproxy/config.toml
WorkingDirectory=/var/lib/ccproxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT
    run install -m 0644 /tmp/ccproxy.service /etc/systemd/system/ccproxy.service
    rm -f /tmp/ccproxy.service

    run systemctl daemon-reload
    run systemctl enable ccproxy

    info "systemd service installed and enabled."
    info ""
    info "Start the service with:"
    info "  systemctl start ccproxy"
    info ""
    info "View auto-generated credentials in the log:"
    info "  journalctl -u ccproxy -n 50"
fi

# ---- done ----

info ""
info "ccproxy ${VERSION_NUM} installed successfully!"
info "  Binary: ${INSTALL_DIR}/ccproxy"
if [ "$WITH_SYSTEMD" = false ]; then
    info ""
    info "Quick start:"
    info "  ${INSTALL_DIR}/ccproxy"
fi
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x install.sh`

- [ ] **Step 3: Verify script syntax**

Run: `sh -n install.sh`
Expected: No output (no syntax errors)

- [ ] **Step 4: Commit**

```bash
git add install.sh
git commit -m "feat: add curl|sh install script with optional systemd setup"
```

---

## Chunk 3: Verification

### Task 3: Final verification

- [ ] **Step 1: Run full test suite**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && go test ./... -race -count=1`
Expected: ALL PASS (except 3 pre-existing config test failures)

- [ ] **Step 2: Verify no remaining binn/ccproxy repo references**

Run: `cd /Users/binn/ZedProjects/token-run-workspace/ccproxy && grep -r '"binn/ccproxy"' --include='*.go' --include='*.yml' --include='*.toml'`
Expected: No output (all references updated). The Go module path `github.com/binn/ccproxy` in import statements and ldflags is intentionally kept.

- [ ] **Step 3: Verify install script parses on the host**

Run: `sh -n install.sh && echo "syntax ok"`
Expected: `syntax ok`

- [ ] **Step 4: Test --help flag**

Run: `sh install.sh --help`
Expected: Print usage information and exit 0

- [ ] **Step 5: Test non-Linux detection (if on macOS)**

Run: `sh install.sh 2>&1; echo "exit: $?"`
Expected: Error message about Linux-only, exit code 1
