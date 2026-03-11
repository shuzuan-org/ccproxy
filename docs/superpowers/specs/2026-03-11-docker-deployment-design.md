# Docker Single-Image Deployment Design

**Date:** 2026-03-11
**Status:** Approved

## Overview

Package ccproxy and Caddy into a single Docker image so users can start a production-ready HTTPS proxy with one command and zero file preparation.

## User Experience

```bash
# Production (HTTPS + auto certs)
docker run -d -p 80:80 -p 443:443 -v ccproxy_data:/data -e DOMAIN=proxy.example.com binn/ccproxy

# Local / internal (HTTP only)
docker run -d -p 80:80 -v ccproxy_data:/data binn/ccproxy

# View auto-generated credentials
docker logs <container>
```

No docker-compose, no Caddyfile, no config file preparation needed.

## Architecture

```
Internet → Caddy (:80/:443) → ccproxy (:3000) → Anthropic API
           TLS termination     API proxy
           Auto certs           OAuth pooling
```

Both processes run inside one container. Caddy is the frontend (HTTPS termination + reverse proxy). ccproxy is the backend (API proxy, admin dashboard, OAuth management).

## Image Structure

### Multi-stage Dockerfile

```
Stage 1: golang:1.25-alpine        → compile ccproxy (CGO_ENABLED=0)
Stage 2: caddy:2-alpine            → copy caddy binary
Stage 3: alpine:3                  → runtime
  WORKDIR /                        ← so relative path "data" resolves to /data
  /usr/bin/caddy                   ← from stage 2
  /usr/bin/ccproxy                 ← from stage 1
  /entrypoint.sh                   ← process manager
  /etc/ssl/certs/ca-certificates   ← for HTTPS to upstream
```

**WORKDIR must be `/`** — ccproxy uses relative path `"data"` for its data directory (oauth tokens, health state, instance registry). With `WORKDIR /`, this resolves to `/data` which is where the Docker volume is mounted.

### Multi-platform

Build with `docker buildx` for `linux/amd64` and `linux/arm64`.

Image name: `binn/ccproxy`

### Estimated size

~57MB (alpine ~7MB + caddy ~40MB + ccproxy ~10MB).

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DOMAIN` | No | (empty) | Domain for Caddy HTTPS. If unset, Caddy listens on HTTP :80 only. |

## Data Volume: /data

All persistent state lives under `/data`, mapped to a Docker volume.

| Path | Purpose | Created by |
|------|---------|------------|
| `/data/config.toml` | Server config | ccproxy (auto-generated on first start) |
| `/data/oauth_tokens.json` | Encrypted OAuth tokens | ccproxy |
| `/data/health_state.json` | Load balancer health state | ccproxy |
| `/data/caddy/` | Caddy certificates and state | Caddy (`XDG_DATA_HOME`) |

## entrypoint.sh Design

### Process management

The entrypoint script manages both processes using a wait loop (NOT exec), so it can relay signals to both:

```bash
#!/bin/sh
set -e

# 1. Generate Caddyfile
if [ -n "$DOMAIN" ]; then
  cat > /etc/caddy/Caddyfile <<EOF
$DOMAIN {
  reverse_proxy localhost:3000
}
EOF
else
  cat > /etc/caddy/Caddyfile <<EOF
:80 {
  reverse_proxy localhost:3000
}
EOF
fi

# 2. Set Caddy data directory inside the volume
export XDG_DATA_HOME=/data/caddy

# 3. Start caddy in background
caddy run --config /etc/caddy/Caddyfile &
CADDY_PID=$!

# 4. Trap signals — forward to both processes
cleanup() {
  kill -TERM "$CCPROXY_PID" 2>/dev/null || true
  kill -TERM "$CADDY_PID" 2>/dev/null || true
  wait "$CCPROXY_PID" 2>/dev/null || true
  wait "$CADDY_PID" 2>/dev/null || true
  exit 0
}
trap cleanup TERM INT

# 5. Start ccproxy in background, wait for it
ccproxy -c /data/config.toml &
CCPROXY_PID=$!
wait "$CCPROXY_PID"
```

Key design choices:
- **No exec** — shell stays as PID 1 to relay signals to both child processes
- **Caddy connects to `localhost:3000`** — both processes are in the same container, no Docker DNS needed
- **Wait loop** — entrypoint waits for ccproxy; on signal, cleanup kills both

## OAuth Token Encryption

Tokens are encrypted with a key derived from `hostname + username`.

**Container considerations:**
- The Dockerfile sets `ENV USER=ccproxy` to ensure a stable username (Alpine containers typically have `$USER` unset, falling back to `"default"` in code)
- **WARNING:** For persistent tokens across container recreation, users MUST use `--hostname ccproxy` (or any fixed value). Without it, the hostname changes on each `docker run`, making previously encrypted tokens undecryptable. The entrypoint prints a warning if no explicit hostname is detected.

## Config Auto-Generation

Already implemented: `config.Load()` calls `ensureConfigFile()` which creates a default `config.toml` if missing. On first start:

1. `/data/config.toml` doesn't exist → created with `host=0.0.0.0, port=3000`
2. `autoGenerate()` fills in `admin_password` and `api_keys`
3. Credentials are persisted to file and printed to stdout (visible in `docker logs`)

## .dockerignore

```
bin/
data/
.git/
.gitignore
*.md
docs/
config.toml
```

## Files to Create

| File | Description |
|------|-------------|
| `Dockerfile` | Multi-stage build: compile ccproxy + copy caddy + alpine runtime |
| `docker/entrypoint.sh` | Process manager: generate Caddyfile, start caddy + ccproxy, relay signals |
| `.dockerignore` | Exclude build artifacts and docs from context |

## Files to Modify

None. The config auto-generation change is already implemented.

## Out of Scope

- Docker Compose file (single `docker run` is the target UX)
- Health check endpoint changes (existing `/health` works as-is)
- GitHub Actions CI for image building (can be added later)
- Kubernetes manifests
