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
