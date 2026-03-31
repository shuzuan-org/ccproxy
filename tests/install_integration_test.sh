#!/bin/bash
# install.sh integration tests
# Runs install.sh in Docker containers to verify all installation modes.
# Usage: bash tests/install_integration_test.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# ---- state ----

PASSED=0
FAILED=0
FAILED_NAMES=()
CONTAINERS=()

# ---- colors ----

green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

# ---- cleanup ----

cleanup() {
    for cid in "${CONTAINERS[@]+"${CONTAINERS[@]}"}"; do
        docker rm -f "$cid" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT

# ---- helpers ----

# Build the test binary once (linux/amd64).
build_test_binary() {
    bold "Building ccproxy linux/amd64 binary..."
    (cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=0.0.0-test -s -w" \
        -o bin/ccproxy-linux-amd64 ./cmd/ccproxy)
}

# Start a plain Debian container with mock systemctl and the binary + install.sh mounted.
start_plain_container() {
    local cid
    cid=$(docker run -d \
        -v "$PROJECT_DIR/bin/ccproxy-linux-amd64:/opt/ccproxy-binary:ro" \
        -v "$PROJECT_DIR/install.sh:/opt/install.sh:ro" \
        debian:bookworm-slim \
        sleep 300)
    CONTAINERS+=("$cid")

    # Install mock systemctl so install.sh doesn't complain about missing systemd.
    docker exec "$cid" bash -c 'cat > /usr/local/bin/systemctl <<\MOCK
#!/bin/sh
echo "systemctl $*" >> /tmp/systemctl.log
exit 0
MOCK
chmod +x /usr/local/bin/systemctl'

    echo "$cid"
}

# Start a systemd container (privileged, with real init).
start_systemd_container() {
    local cid
    cid=$(docker run -d --privileged \
        -v "$PROJECT_DIR/bin/ccproxy-linux-amd64:/opt/ccproxy-binary:ro" \
        -v "$PROJECT_DIR/install.sh:/opt/install.sh:ro" \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
        jrei/systemd-debian:bookworm \
        /lib/systemd/systemd)
    CONTAINERS+=("$cid")

    # Wait for systemd to boot.
    local retries=0
    while ! docker exec "$cid" systemctl is-system-running --wait 2>/dev/null | grep -qE "running|degraded"; do
        retries=$((retries + 1))
        if [ "$retries" -gt 30 ]; then
            red "systemd container failed to boot"
            return 1
        fi
        sleep 1
    done

    echo "$cid"
}

# Create a fake GitHub release tarball + checksums inside the container,
# and produce a patched install.sh that copies local files instead of downloading.
prepare_local_install() {
    local cid="$1"
    docker exec "$cid" bash -c 'set -e
mkdir -p /tmp/release
cp /opt/ccproxy-binary /tmp/release/ccproxy
cd /tmp/release
tar czf ccproxy_0.0.0-test_linux_amd64.tar.gz ccproxy
sha256sum ccproxy_0.0.0-test_linux_amd64.tar.gz > checksums.txt

# Patch install.sh: replace download() body with local file copies.
# Strategy: replace the two download calls with cp from local release dir.
sed \
    -e "s|download \"\$DOWNLOAD_URL\" \"\${TMPDIR}/\${ARCHIVE}\"|cp /tmp/release/ccproxy_0.0.0-test_linux_amd64.tar.gz \"\${TMPDIR}/\${ARCHIVE}\"|" \
    -e "s|download \"\$CHECKSUMS_URL\" \"\${TMPDIR}/checksums.txt\"|cp /tmp/release/checksums.txt \"\${TMPDIR}/checksums.txt\"|" \
    /opt/install.sh > /tmp/patched_install.sh
chmod +x /tmp/patched_install.sh'
}

# Run the patched install.sh with given args (--version is always prepended).
run_install() {
    local cid="$1"
    shift
    docker exec "$cid" sh /tmp/patched_install.sh --version v0.0.0-test "$@" 2>&1
}

assert_contains() {
    local output="$1"
    local expected="$2"
    local msg="${3:-}"
    if echo "$output" | grep -qF "$expected"; then
        return 0
    else
        red "  ASSERT FAILED: output does not contain '$expected'"
        [ -n "$msg" ] && red "  ($msg)"
        return 1
    fi
}

assert_exit_code() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-}"
    if [ "$actual" -eq "$expected" ]; then
        return 0
    else
        red "  ASSERT FAILED: exit code $actual != expected $expected"
        [ -n "$msg" ] && red "  ($msg)"
        return 1
    fi
}

record_pass() {
    green "  PASS: $1"
    PASSED=$((PASSED + 1))
}

record_fail() {
    red "  FAIL: $1"
    FAILED=$((FAILED + 1))
    FAILED_NAMES+=("$1")
}

# ---- tests ----

test_help() {
    bold "[Test 1] --help output"
    local cid
    cid=$(start_plain_container)

    local output
    output=$(docker exec "$cid" sh /opt/install.sh --help 2>&1) || true

    local ok=true
    assert_contains "$output" "--domain" || ok=false
    assert_contains "$output" "--with-systemd" || ok=false
    assert_contains "$output" "--dry-run" || ok=false

    if [ "$ok" = true ]; then
        record_pass "help output"
    else
        record_fail "help output"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_binary_only() {
    bold "[Test 2] Binary-only install"
    local cid
    cid=$(start_plain_container)
    prepare_local_install "$cid"

    local output
    output=$(run_install "$cid" 2>&1)

    local ok=true

    # Binary exists and is executable.
    docker exec "$cid" test -x /opt/ccproxy/bin/ccproxy || { red "  binary not executable"; ok=false; }

    # ccproxy version outputs version string.
    local ver_output
    ver_output=$(docker exec "$cid" /opt/ccproxy/bin/ccproxy version 2>&1) || true
    assert_contains "$ver_output" "0.0.0-test" || ok=false

    if [ "$ok" = true ]; then
        record_pass "binary-only install"
    else
        record_fail "binary-only install"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_systemd_setup() {
    bold "[Test 3] --with-systemd setup"
    local cid
    cid=$(start_plain_container)
    prepare_local_install "$cid"

    local output
    output=$(run_install "$cid" --with-systemd 2>&1)

    local ok=true

    # User ccproxy exists.
    docker exec "$cid" id ccproxy >/dev/null 2>&1 || { red "  user ccproxy not found"; ok=false; }

    # /opt/ccproxy/etc permissions: 0700, owned by ccproxy.
    local etc_stat
    etc_stat=$(docker exec "$cid" stat -c '%a %U' /opt/ccproxy/etc 2>&1)
    assert_contains "$etc_stat" "700 ccproxy" "expected /opt/ccproxy/etc 700 ccproxy, got: $etc_stat" || ok=false

    # /opt/ccproxy permissions: 0700, owned by ccproxy.
    local var_stat
    var_stat=$(docker exec "$cid" stat -c '%a %U' /opt/ccproxy 2>&1)
    assert_contains "$var_stat" "700 ccproxy" "expected /opt/ccproxy 700 ccproxy, got: $var_stat" || ok=false

    # Unit file exists and contains key directives.
    local unit
    unit=$(docker exec "$cid" cat /etc/systemd/system/ccproxy.service 2>&1) || { red "  unit file missing"; ok=false; }
    assert_contains "$unit" "User=ccproxy" || ok=false
    assert_contains "$unit" "ExecStart=/opt/ccproxy/bin/ccproxy" || ok=false
    assert_contains "$unit" "WorkingDirectory=/opt/ccproxy" || ok=false

    if [ "$ok" = true ]; then
        record_pass "systemd setup"
    else
        record_fail "systemd setup"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_domain_deploy() {
    bold "[Test 4] --domain localhost (full HTTPS deploy)"
    local cid
    cid=$(start_systemd_container)
    prepare_local_install "$cid"

    # Install curl and gpg for caddy repo setup.
    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl gpg' >/dev/null 2>&1

    local output
    output=$(run_install "$cid" --domain localhost 2>&1)

    local ok=true

    # Caddy should be installed and running.
    docker exec "$cid" command -v caddy >/dev/null 2>&1 || { red "  caddy not installed"; ok=false; }
    local caddy_status
    caddy_status=$(docker exec "$cid" systemctl is-active caddy 2>&1) || true
    assert_contains "$caddy_status" "active" "caddy not active: $caddy_status" || ok=false

    # Caddyfile should contain localhost and reverse_proxy.
    local caddyfile
    caddyfile=$(docker exec "$cid" cat /etc/caddy/Caddyfile 2>&1) || true
    assert_contains "$caddyfile" "localhost" || ok=false
    assert_contains "$caddyfile" "reverse_proxy" || ok=false

    # ccproxy service should be active.
    local proxy_status
    proxy_status=$(docker exec "$cid" systemctl is-active ccproxy 2>&1) || true
    assert_contains "$proxy_status" "active" "ccproxy not active: $proxy_status" || ok=false

    # Health check via HTTPS (self-signed, so -k).
    sleep 2
    local health
    health=$(docker exec "$cid" curl -sk https://localhost/health 2>&1) || true
    assert_contains "$health" "ok" "health check failed: $health" || ok=false

    if [ "$ok" = true ]; then
        record_pass "domain deploy"
    else
        record_fail "domain deploy"
    fi

    # Return container ID for test 5 (don't destroy yet).
    echo "$cid"
}

test_idempotent_domain() {
    bold "[Test 5] Idempotent --domain (re-run)"
    local cid="$1"

    local output exit_code=0
    output=$(run_install "$cid" --domain localhost 2>&1) || exit_code=$?

    local ok=true

    # Should succeed (exit 0).
    assert_exit_code "$exit_code" 0 "re-run should succeed" || ok=false

    # Should mention already installed/exists for user or caddy.
    if echo "$output" | grep -qiE "already (installed|exists)|skipping"; then
        true
    else
        red "  expected 'already installed/exists/skipping' in output"
        ok=false
    fi

    if [ "$ok" = true ]; then
        record_pass "idempotent domain"
    else
        record_fail "idempotent domain"
    fi
}

test_non_root_rejected() {
    bold "[Test 6] Non-root rejection"
    local cid
    cid=$(start_plain_container)

    # Create a non-root user.
    docker exec "$cid" useradd -m testuser

    # Run install.sh as non-root (default install dir /opt/ccproxy/bin is not writable).
    local output exit_code=0
    output=$(docker exec -u testuser "$cid" sh /opt/install.sh --version v0.0.0-test 2>&1) || exit_code=$?

    local ok=true

    # Should fail.
    if [ "$exit_code" -eq 0 ]; then
        red "  expected non-zero exit code, got 0"
        ok=false
    fi

    # Error should mention root or cannot write.
    if echo "$output" | grep -qiE "root|cannot write"; then
        true
    else
        red "  expected 'root' or 'cannot write' in error output"
        ok=false
    fi

    if [ "$ok" = true ]; then
        record_pass "non-root rejection"
    else
        record_fail "non-root rejection"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

# ---- main ----

bold "=== ccproxy install.sh integration tests ==="
echo ""

# Pre-flight: docker must be available.
if ! command -v docker >/dev/null 2>&1; then
    red "docker is required to run these tests"
    exit 1
fi

build_test_binary

# Run tests 1-3, 6 (plain containers, fast).
test_help
test_binary_only
test_systemd_setup
test_non_root_rejected

# Run tests 4-5 (systemd container, slower).
DOMAIN_CID=$(test_domain_deploy)
if [ -n "$DOMAIN_CID" ]; then
    test_idempotent_domain "$DOMAIN_CID"
    docker rm -f "$DOMAIN_CID" >/dev/null 2>&1
fi

# ---- summary ----

echo ""
bold "=== Results ==="
green "Passed: $PASSED"
if [ "$FAILED" -gt 0 ]; then
    red "Failed: $FAILED"
    for name in "${FAILED_NAMES[@]}"; do
        red "  - $name"
    done
    exit 1
else
    green "All tests passed!"
    exit 0
fi
