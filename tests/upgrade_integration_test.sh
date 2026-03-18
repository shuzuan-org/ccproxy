#!/bin/bash
# upgrade/auto-update integration tests
# Runs ccproxy in Docker containers to verify upgrade CLI and admin API behavior.
# Usage: bash tests/upgrade_integration_test.sh
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

ADMIN_PASS="testpass123"
BINARY_VERSION="0.0.1-test"
V2_VERSION="0.0.2-test"

build_test_binary() {
    bold "Building ccproxy linux/amd64 binary (v${BINARY_VERSION})..."
    (cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=${BINARY_VERSION} -s -w" \
        -o bin/ccproxy-linux-amd64 ./cmd/ccproxy)
}

build_dev_binary() {
    bold "Building ccproxy linux/amd64 binary (dev)..."
    (cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=dev -s -w" \
        -o bin/ccproxy-linux-amd64-dev ./cmd/ccproxy)
}

build_v2_binary() {
    bold "Building ccproxy linux/amd64 binary (v${V2_VERSION})..."
    (cd "$PROJECT_DIR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
        -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=${V2_VERSION} -s -w" \
        -o bin/ccproxy-linux-amd64-v2 ./cmd/ccproxy)
}

prepare_mock_release() {
    bold "Preparing mock release artifacts (v${V2_VERSION})..."
    local release_dir="$PROJECT_DIR/bin/mock-release"
    rm -rf "$release_dir"
    mkdir -p "$release_dir"

    # Create tarball containing v2 binary named "ccproxy".
    local tarball_name="ccproxy_${V2_VERSION}_linux_amd64.tar.gz"
    cp "$PROJECT_DIR/bin/ccproxy-linux-amd64-v2" "$PROJECT_DIR/bin/_ccproxy_tar_tmp"
    (cd "$PROJECT_DIR/bin" && mv _ccproxy_tar_tmp ccproxy && \
        tar czf "mock-release/$tarball_name" ccproxy && \
        rm ccproxy)

    # Generate SHA-256 checksums (portable: macOS shasum / Linux sha256sum).
    (cd "$release_dir" && \
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$tarball_name" > checksums.txt
        else
            shasum -a 256 "$tarball_name" > checksums.txt
        fi)

    bold "  tarball: $release_dir/$tarball_name"
    bold "  checksums: $(cat "$release_dir/checksums.txt")"
}

# Start a container with ccproxy binary and a config file.
# Args: [binary_path]
start_container() {
    local binary="${1:-/opt/ccproxy}"
    local cid
    cid=$(docker run -d \
        -v "$PROJECT_DIR/bin/ccproxy-linux-amd64:/opt/ccproxy:ro" \
        -v "$PROJECT_DIR/bin/ccproxy-linux-amd64-dev:/opt/ccproxy-dev:ro" \
        debian:bookworm-slim \
        sleep 300)
    CONTAINERS+=("$cid")

    # Create config with known admin password.
    docker exec "$cid" bash -c "
mkdir -p /etc/ccproxy /var/lib/ccproxy
cat > /etc/ccproxy/config.toml <<'EOF'
[server]
host = \"127.0.0.1\"
port = 3000
admin_password = \"${ADMIN_PASS}\"

[[api_keys]]
key = \"sk-test00000000000000000000000000000000000000000000000000000000test\"
name = \"test\"
enabled = true
EOF
"

    echo "$cid"
}

# Start ccproxy as a background process inside the container.
# Args: cid [binary_path] [extra_flags...]
start_ccproxy() {
    local cid="$1"
    local binary="${2:-/opt/ccproxy}"
    shift 2 || shift 1 || true
    docker exec -d "$cid" "$binary" -c /etc/ccproxy/config.toml "$@"
    # Wait for it to be ready.
    local retries=0
    while ! docker exec "$cid" sh -c "curl -sf http://127.0.0.1:3000/health >/dev/null 2>&1" ; do
        retries=$((retries + 1))
        if [ "$retries" -gt 20 ]; then
            red "  ccproxy failed to start"
            docker exec "$cid" cat /tmp/ccproxy.log 2>/dev/null || true
            return 1
        fi
        sleep 0.5
    done
}

# curl wrapper for admin API (with auth).
admin_curl() {
    local cid="$1"
    local method="$2"
    local path="$3"
    docker exec "$cid" curl -sf -X "$method" \
        -u "admin:${ADMIN_PASS}" \
        "http://127.0.0.1:3000${path}" 2>&1
}

# curl wrapper that captures HTTP status code.
admin_curl_status() {
    local cid="$1"
    local method="$2"
    local path="$3"
    docker exec "$cid" curl -s -o /dev/null -w '%{http_code}' -X "$method" \
        -u "admin:${ADMIN_PASS}" \
        "http://127.0.0.1:3000${path}" 2>&1
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

test_upgrade_check_dev_version() {
    bold "[Test 1] CLI 'upgrade --check' with dev version"
    local cid
    cid=$(start_container)

    # Run upgrade --check with dev binary (should warn + exit cleanly even if GitHub unreachable).
    local output exit_code=0
    output=$(docker exec "$cid" /opt/ccproxy-dev upgrade --check 2>&1) || exit_code=$?

    local ok=true

    # Should contain dev warning.
    assert_contains "$output" "dev" "should mention dev version" || ok=false
    # Should show "Current version: dev".
    assert_contains "$output" "Current version: dev" || ok=false

    if [ "$ok" = true ]; then
        record_pass "upgrade --check dev version"
    else
        record_fail "upgrade --check dev version"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_upgrade_check_versioned() {
    bold "[Test 2] CLI 'upgrade --check' with versioned binary"
    local cid
    cid=$(start_container)

    # Run upgrade --check (will try to hit GitHub; may succeed or fail depending on network).
    local output exit_code=0
    output=$(docker exec "$cid" /opt/ccproxy upgrade --check 2>&1) || exit_code=$?

    local ok=true

    # Should print current version.
    assert_contains "$output" "Current version: ${BINARY_VERSION}" || ok=false
    # Should print "Checking" message.
    assert_contains "$output" "Checking" || ok=false
    # Should NOT contain "dev" warning.
    if echo "$output" | grep -qF "warning: running dev version"; then
        red "  should not contain dev warning"
        ok=false
    fi

    if [ "$ok" = true ]; then
        record_pass "upgrade --check versioned"
    else
        record_fail "upgrade --check versioned"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_api_update_status() {
    bold "[Test 3] Admin API GET /api/update/status"
    local cid
    cid=$(start_container)

    # Install curl.
    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl' >/dev/null 2>&1

    start_ccproxy "$cid" /opt/ccproxy

    local output
    output=$(admin_curl "$cid" GET /api/update/status)

    local ok=true

    # Should contain current_version field with our version.
    assert_contains "$output" "current_version" || ok=false
    assert_contains "$output" "${BINARY_VERSION}" || ok=false
    # Should contain auto_update field.
    assert_contains "$output" "auto_update" || ok=false

    if [ "$ok" = true ]; then
        record_pass "API /api/update/status"
    else
        record_fail "API /api/update/status"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_api_update_status_method_not_allowed() {
    bold "[Test 4] Admin API POST /api/update/status → 405"
    local cid
    cid=$(start_container)

    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl' >/dev/null 2>&1

    start_ccproxy "$cid" /opt/ccproxy

    local status
    status=$(admin_curl_status "$cid" POST /api/update/status)

    local ok=true
    if [ "$status" = "405" ]; then
        true
    else
        red "  expected HTTP 405, got $status"
        ok=false
    fi

    if [ "$ok" = true ]; then
        record_pass "API /api/update/status 405"
    else
        record_fail "API /api/update/status 405"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_api_update_apply_docker() {
    bold "[Test 5] Admin API POST /api/update/apply in Docker → 503"
    local cid
    cid=$(start_container)

    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl' >/dev/null 2>&1

    # Ensure /.dockerenv exists (it should in a Docker container).
    docker exec "$cid" touch /.dockerenv

    start_ccproxy "$cid" /opt/ccproxy

    local status
    status=$(admin_curl_status "$cid" POST /api/update/apply)

    local ok=true
    if [ "$status" = "503" ]; then
        true
    else
        red "  expected HTTP 503, got $status"
        ok=false
    fi

    # Also verify the error message mentions Docker.
    local body
    body=$(docker exec "$cid" curl -s -X POST \
        -u "admin:${ADMIN_PASS}" \
        "http://127.0.0.1:3000/api/update/apply" 2>&1) || true
    assert_contains "$body" "Docker" "error should mention Docker" || ok=false

    if [ "$ok" = true ]; then
        record_pass "API /api/update/apply Docker 503"
    else
        record_fail "API /api/update/apply Docker 503"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_api_update_check_graceful() {
    bold "[Test 6] Admin API POST /api/update/check (graceful error)"
    local cid
    cid=$(start_container)

    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl' >/dev/null 2>&1

    start_ccproxy "$cid" /opt/ccproxy

    # POST /api/update/check will try to reach GitHub API.
    # It may succeed or fail, but should always return valid JSON.
    local status
    status=$(admin_curl_status "$cid" POST /api/update/check)

    local ok=true

    # Should return either 200 (success) or 500 (GitHub unreachable), not crash.
    if [ "$status" = "200" ] || [ "$status" = "500" ]; then
        true
    else
        red "  expected HTTP 200 or 500, got $status"
        ok=false
    fi

    # Body should be valid JSON (contains { }).
    local body
    body=$(docker exec "$cid" curl -s -X POST \
        -u "admin:${ADMIN_PASS}" \
        "http://127.0.0.1:3000/api/update/check" 2>&1) || true
    if echo "$body" | grep -q '{'; then
        true
    else
        red "  response is not JSON: $body"
        ok=false
    fi

    if [ "$ok" = true ]; then
        record_pass "API /api/update/check graceful"
    else
        record_fail "API /api/update/check graceful"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_auto_update_disabled_config() {
    bold "[Test 7] auto_update=false reflected in status"
    local cid
    cid=$(start_container)

    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl' >/dev/null 2>&1

    # Override config with auto_update = false.
    docker exec "$cid" bash -c "cat > /etc/ccproxy/config.toml <<'EOF'
[server]
host = \"127.0.0.1\"
port = 3000
admin_password = \"${ADMIN_PASS}\"
auto_update = false

[[api_keys]]
key = \"sk-test00000000000000000000000000000000000000000000000000000000test\"
name = \"test\"
enabled = true
EOF
"

    start_ccproxy "$cid" /opt/ccproxy

    local output
    output=$(admin_curl "$cid" GET /api/update/status)

    local ok=true
    assert_contains "$output" '"auto_update":false' "auto_update should be false" || ok=false

    if [ "$ok" = true ]; then
        record_pass "auto_update=false in status"
    else
        record_fail "auto_update=false in status"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

# Start a container with python3 + curl + mock release artifacts for E2E upgrade tests.
# The v1 binary is copied to a writable path so go-selfupdate can replace it.
start_upgrade_container() {
    local cid
    cid=$(docker run -d \
        -v "$PROJECT_DIR/bin/ccproxy-linux-amd64:/opt/ccproxy-v1:ro" \
        -v "$PROJECT_DIR/bin/mock-release:/opt/mock-release:ro" \
        -v "$SCRIPT_DIR/mock_github_api.py:/opt/mock_github_api.py:ro" \
        debian:bookworm-slim \
        sleep 600)
    CONTAINERS+=("$cid")

    # Install python3 + curl.
    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq python3 curl procps' >/dev/null 2>&1

    # Copy v1 binary to writable location (go-selfupdate replaces in-place).
    docker exec "$cid" cp /opt/ccproxy-v1 /usr/local/bin/ccproxy
    docker exec "$cid" chmod +x /usr/local/bin/ccproxy

    # Remove /.dockerenv so updater does not refuse.
    docker exec "$cid" rm -f /.dockerenv

    # Create data directory.
    docker exec "$cid" mkdir -p /etc/ccproxy /var/lib/ccproxy

    echo "$cid"
}

# Start mock GitHub API inside the container. Waits until it responds.
start_mock_api() {
    local cid="$1"
    docker exec -d -e MOCK_VERSION="$V2_VERSION" -e MOCK_REPO="shuzuan-org/ccproxy" \
        -e MOCK_RELEASE_DIR="/opt/mock-release" -e MOCK_PORT=9999 \
        "$cid" python3 /opt/mock_github_api.py

    local retries=0
    while ! docker exec "$cid" curl -sf http://127.0.0.1:9999/repos/shuzuan-org/ccproxy/releases >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [ "$retries" -gt 20 ]; then
            red "  mock API failed to start"
            return 1
        fi
        sleep 0.5
    done
}

test_api_update_apply_method_not_allowed() {
    bold "[Test 8] Admin API GET /api/update/apply → 405"
    local cid
    cid=$(start_container)

    docker exec "$cid" bash -c 'apt-get update -qq && apt-get install -y -qq curl' >/dev/null 2>&1

    start_ccproxy "$cid" /opt/ccproxy

    local status
    status=$(admin_curl_status "$cid" GET /api/update/apply)

    local ok=true
    if [ "$status" = "405" ]; then
        true
    else
        red "  expected HTTP 405, got $status"
        ok=false
    fi

    if [ "$ok" = true ]; then
        record_pass "API /api/update/apply 405"
    else
        record_fail "API /api/update/apply 405"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_api_full_upgrade() {
    bold "[Test 9] Admin API full upgrade (check → apply → verify binary)"
    local cid
    cid=$(start_upgrade_container)

    # Config: auto_update=false, update_api_url points to mock.
    docker exec "$cid" bash -c "cat > /etc/ccproxy/config.toml <<'EOF'
[server]
host = \"127.0.0.1\"
port = 3000
admin_password = \"${ADMIN_PASS}\"
auto_update = false
update_api_url = \"http://127.0.0.1:9999/\"

[[api_keys]]
key = \"sk-test00000000000000000000000000000000000000000000000000000000test\"
name = \"test\"
enabled = true
EOF
"

    start_mock_api "$cid"
    start_ccproxy "$cid" /usr/local/bin/ccproxy

    local ok=true

    # 1. POST /api/update/check → should find v0.0.2-test.
    local check_output
    check_output=$(admin_curl "$cid" POST /api/update/check) || { red "  check request failed"; ok=false; }
    if [ "$ok" = true ]; then
        assert_contains "$check_output" "$V2_VERSION" "check should find $V2_VERSION" || ok=false
    fi

    # 2. POST /api/update/apply → should apply update.
    local apply_output
    apply_output=$(admin_curl "$cid" POST /api/update/apply) || { red "  apply request failed"; ok=false; }
    if [ "$ok" = true ]; then
        assert_contains "$apply_output" '"updated":true' "apply should return updated:true" || ok=false
    fi

    # 3. Wait for ccproxy to exit (SIGTERM after update).
    local retries=0
    while docker exec "$cid" pgrep -x ccproxy >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [ "$retries" -gt 30 ]; then
            red "  ccproxy did not exit after apply"
            ok=false
            break
        fi
        sleep 1
    done

    # 4. Verify binary version.
    local version_output
    version_output=$(docker exec "$cid" /usr/local/bin/ccproxy version 2>&1)
    assert_contains "$version_output" "$V2_VERSION" "binary should be v${V2_VERSION}" || ok=false

    if [ "$ok" = true ]; then
        record_pass "API full upgrade"
    else
        record_fail "API full upgrade"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

test_auto_update_background() {
    bold "[Test 10] Background auto-update (initial 30s delay)"
    local cid
    cid=$(start_upgrade_container)

    # Config: auto_update=true, update_api_url points to mock.
    docker exec "$cid" bash -c "cat > /etc/ccproxy/config.toml <<'EOF'
[server]
host = \"127.0.0.1\"
port = 3000
admin_password = \"${ADMIN_PASS}\"
auto_update = true
update_check_interval = \"5m\"
update_api_url = \"http://127.0.0.1:9999/\"

[[api_keys]]
key = \"sk-test00000000000000000000000000000000000000000000000000000000test\"
name = \"test\"
enabled = true
EOF
"

    start_mock_api "$cid"
    start_ccproxy "$cid" /usr/local/bin/ccproxy

    local ok=true

    # Wait for auto-update: 30s initial delay + check + download + apply.
    bold "  Waiting for auto-update (up to 60s)..."
    local retries=0
    while docker exec "$cid" pgrep -x ccproxy >/dev/null 2>&1; do
        retries=$((retries + 1))
        if [ "$retries" -gt 60 ]; then
            red "  ccproxy did not auto-update within 60s"
            ok=false
            break
        fi
        sleep 1
    done

    if [ "$ok" = true ]; then
        bold "  ccproxy exited after ~${retries}s"
    fi

    # Verify binary version.
    local version_output
    version_output=$(docker exec "$cid" /usr/local/bin/ccproxy version 2>&1)
    assert_contains "$version_output" "$V2_VERSION" "binary should be v${V2_VERSION}" || ok=false

    if [ "$ok" = true ]; then
        record_pass "auto-update background"
    else
        record_fail "auto-update background"
    fi

    docker rm -f "$cid" >/dev/null 2>&1
}

# ---- main ----

bold "=== ccproxy upgrade/auto-update integration tests ==="
echo ""

if ! command -v docker >/dev/null 2>&1; then
    red "docker is required to run these tests"
    exit 1
fi

build_test_binary
build_dev_binary
build_v2_binary
prepare_mock_release

test_upgrade_check_dev_version
test_upgrade_check_versioned
test_api_update_status
test_api_update_status_method_not_allowed
test_api_update_apply_docker
test_api_update_check_graceful
test_auto_update_disabled_config
test_api_update_apply_method_not_allowed
test_api_full_upgrade
test_auto_update_background

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
