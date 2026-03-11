# Docker Single-Image Deployment Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package ccproxy + Caddy into a single Docker image for one-command deployment.

**Architecture:** Multi-stage Dockerfile builds ccproxy from source, copies Caddy binary from official image, runs both in Alpine with a shell entrypoint that manages process lifecycle and signal forwarding. All persistent data stored under `/data` volume.

**Tech Stack:** Docker multi-stage build, Alpine Linux, Caddy 2, Go 1.25

**Spec:** `docs/superpowers/specs/2026-03-11-docker-deployment-design.md`

---

## Chunk 1: Core Docker Files

### Task 1: Create .dockerignore

**Files:**
- Create: `.dockerignore`

- [ ] **Step 1: Create .dockerignore**

```
bin/
data/
.git/
.gitignore
*.md
docs/
config.toml
```

- [ ] **Step 2: Commit**

```bash
git add .dockerignore
git commit -m "chore: add .dockerignore for Docker builds"
```

---

### Task 2: Create entrypoint.sh

**Files:**
- Create: `docker/entrypoint.sh`

- [ ] **Step 1: Create docker/ directory and entrypoint.sh**

```bash
#!/bin/sh
set -e

# Warn if hostname looks like a Docker-generated random ID
if echo "$HOSTNAME" | grep -qE '^[0-9a-f]{12}$'; then
  echo "WARNING: No fixed --hostname set. OAuth tokens will break on container recreation." >&2
  echo "WARNING: Use: docker run --hostname ccproxy ..." >&2
fi

# Generate Caddyfile based on DOMAIN env var
mkdir -p /etc/caddy
if [ -n "$DOMAIN" ]; then
  cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
  reverse_proxy localhost:3000
}
EOF
  echo "Caddy: HTTPS mode for $DOMAIN"
else
  cat > /etc/caddy/Caddyfile <<EOF
:80 {
  reverse_proxy localhost:3000
}
EOF
  echo "Caddy: HTTP-only mode (no DOMAIN set)"
fi

# Caddy stores certs inside the data volume
export XDG_DATA_HOME=/data/caddy

# Start Caddy in background
caddy run --config /etc/caddy/Caddyfile &
CADDY_PID=$!

# Forward signals to both processes (guard against empty PIDs)
cleanup() {
  [ -n "$CCPROXY_PID" ] && kill -TERM "$CCPROXY_PID" 2>/dev/null || true
  [ -n "$CADDY_PID" ] && kill -TERM "$CADDY_PID" 2>/dev/null || true
  [ -n "$CCPROXY_PID" ] && wait "$CCPROXY_PID" 2>/dev/null || true
  [ -n "$CADDY_PID" ] && wait "$CADDY_PID" 2>/dev/null || true
  exit 0
}
trap cleanup TERM INT

# Start ccproxy in background, then wait
ccproxy -c /data/config.toml &
CCPROXY_PID=$!
wait "$CCPROXY_PID"
```

- [ ] **Step 2: Make it executable**

Run: `chmod +x docker/entrypoint.sh`

- [ ] **Step 3: Commit**

```bash
git add docker/entrypoint.sh
git commit -m "feat(docker): add entrypoint script for caddy + ccproxy process management"
```

---

### Task 3: Create Dockerfile

**Files:**
- Create: `Dockerfile`

- [ ] **Step 1: Create multi-stage Dockerfile**

```dockerfile
# Stage 1: Build ccproxy
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/binn/ccproxy/internal/cli.Version=${VERSION} -s -w" \
    -o /ccproxy ./cmd/ccproxy

# Stage 2: Get Caddy binary
FROM caddy:2-alpine AS caddy

# Stage 3: Runtime
FROM alpine:3
RUN apk add --no-cache ca-certificates

COPY --from=builder /ccproxy /usr/bin/ccproxy
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY docker/entrypoint.sh /entrypoint.sh

ENV USER=ccproxy
WORKDIR /

VOLUME /data
EXPOSE 80 443

ENTRYPOINT ["/entrypoint.sh"]
```

- [ ] **Step 2: Verify build succeeds locally**

Run: `docker build -t ccproxy-test .`
Expected: Build completes without errors.

- [ ] **Step 3: Commit**

```bash
git add Dockerfile
git commit -m "feat(docker): add multi-stage Dockerfile with caddy + ccproxy"
```

---

## Chunk 2: Build Targets and Validation

### Task 4: Add Docker build targets to Makefile

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add docker-build and docker-run targets**

Append to existing Makefile:

```makefile
docker-build:
	docker build --build-arg VERSION=$(VERSION) -t binn/ccproxy:$(VERSION) -t binn/ccproxy:latest .

docker-run:
	docker run --rm -p 80:80 -p 443:443 -v ccproxy_data:/data --hostname ccproxy binn/ccproxy:latest

docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t binn/ccproxy:$(VERSION) -t binn/ccproxy:latest \
		--push .
```

Update `.PHONY` line to include new targets:

```makefile
.PHONY: build build-linux run test clean docker-build docker-run docker-push
```

- [ ] **Step 2: Commit**

```bash
git add Makefile
git commit -m "feat(docker): add docker-build, docker-run, docker-push make targets"
```

---

### Task 5: Test Docker image end-to-end

- [ ] **Step 1: Build the image**

Run: `make docker-build`
Expected: Image builds successfully.

- [ ] **Step 2: Start container in HTTP mode (no DOMAIN)**

Run: `docker run --rm -d --name ccproxy-test -p 8080:80 -v ccproxy_test_data:/data --hostname ccproxy binn/ccproxy:latest`
Expected: Container starts without errors.

- [ ] **Step 3: Verify ccproxy is running**

Run: `curl -s http://localhost:8080/health`
Expected: Health check returns 200 OK (Caddy proxies to ccproxy:3000).

- [ ] **Step 4: Verify auto-generated credentials in logs**

Run: `docker logs ccproxy-test 2>&1 | grep -A5 "Auto-generated"`
Expected: Shows admin_password and API key.

- [ ] **Step 5: Verify config was persisted to volume**

Run: `docker exec ccproxy-test cat /data/config.toml`
Expected: Shows config with auto-generated admin_password and api_keys.

- [ ] **Step 6: Cleanup**

Run: `docker stop ccproxy-test && docker volume rm ccproxy_test_data`

- [ ] **Step 7: Commit all files (if any fixes needed)**

```bash
git add -A
git commit -m "fix(docker): adjustments from end-to-end testing"
```
