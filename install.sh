#!/bin/sh
set -e

# ccproxy install script
# Usage: curl -fsSL https://raw.githubusercontent.com/shuzuan-org/ccproxy/master/install.sh | sh
#   or:  curl -fsSL ... | sh -s -- --with-systemd --version 1.0.0
#   or:  curl -fsSL ... | sudo sh -s -- --domain proxy.example.com

REPO="shuzuan-org/ccproxy"
INSTALL_DIR="/usr/local/bin"
WITH_SYSTEMD=false
DRY_RUN=false
VERSION=""
DOMAIN=""

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
        --domain)
            DOMAIN="$2"
            WITH_SYSTEMD=true
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
  --domain DOMAIN       Full HTTPS deploy with Caddy (implies --with-systemd)
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
    # Check if install dir (or its parent) is writable.
    if [ -d "$INSTALL_DIR" ]; then
        if [ ! -w "$INSTALL_DIR" ]; then
            err "cannot write to $INSTALL_DIR — run as root or use --install-dir"
        fi
    elif [ ! -w "$(dirname "$INSTALL_DIR")" ]; then
        err "cannot create $INSTALL_DIR — run as root or use --install-dir"
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

# ---- caddy helpers ----

install_caddy() {
    if command -v caddy > /dev/null 2>&1; then
        info "Caddy already installed, skipping."
        return
    fi

    info "Installing Caddy via package manager..."
    if command -v apt-get > /dev/null 2>&1; then
        run apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | \
            gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | \
            tee /etc/apt/sources.list.d/caddy-stable.list
        run apt-get update
        run apt-get install -y caddy
    elif command -v dnf > /dev/null 2>&1; then
        run dnf install -y 'dnf-command(copr)'
        run dnf copr enable -y @caddy/caddy
        run dnf install -y caddy
    else
        err "unsupported package manager for Caddy (need apt-get or dnf)"
    fi
}

setup_caddy() {
    info "Configuring Caddy for ${DOMAIN}..."

    # Caddy package creates /etc/caddy/ during install
    CADDY_TMP=$(mktemp)
    cat > "$CADDY_TMP" <<CADDYEOF
${DOMAIN} {
	reverse_proxy localhost:3000
}
CADDYEOF
    run install -m 0644 "$CADDY_TMP" /etc/caddy/Caddyfile
    rm -f "$CADDY_TMP"

    run systemctl enable caddy
    run systemctl restart caddy
    info "Caddy configured: https://${DOMAIN} -> localhost:3000"
}

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

    # Write systemd unit file to a secure temp file.
    UNIT_TMP=$(mktemp)
    cat > "$UNIT_TMP" <<UNIT
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
    run install -m 0644 "$UNIT_TMP" /etc/systemd/system/ccproxy.service
    rm -f "$UNIT_TMP"

    run systemctl daemon-reload
    run systemctl enable ccproxy

    info "systemd service installed and enabled."

    if [ -z "$DOMAIN" ]; then
        info ""
        info "Start the service with:"
        info "  systemctl start ccproxy"
        info ""
        info "View auto-generated credentials in the log:"
        info "  journalctl -u ccproxy -n 50"
    fi
fi

# ---- caddy setup (optional, requires --domain) ----

if [ -n "$DOMAIN" ]; then
    install_caddy
    setup_caddy
    run systemctl start ccproxy
    info ""
    info "ccproxy ${VERSION_NUM} deployed with HTTPS!"
    info "  URL: https://${DOMAIN}"
    info "  Caddy auto-obtains TLS cert from Let's Encrypt."
    info "  Ensure DNS for ${DOMAIN} points to this server."
    info ""
    info "View auto-generated credentials:"
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
