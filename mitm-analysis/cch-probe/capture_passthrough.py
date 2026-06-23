#!/usr/bin/env python3
"""capture_passthrough.py — zero-dependency HTTP capture proxy.

The local `claude` CLI already targets a configurable upstream via
ANTHROPIC_BASE_URL, so we do NOT need mitmproxy/TLS interception. We run a
plain localhost HTTP proxy that:

  1. saves every /v1/messages request body to captured/<ts>.bin (+ .meta)
  2. forwards the request verbatim (method, path, headers, body) to the real
     HTTPS upstream
  3. streams the upstream response back to the client unchanged

Point the CLI at us:
    ANTHROPIC_BASE_URL=http://127.0.0.1:8788 claude "say hi"

The captured body is the client's ORIGINAL request — the ground truth for
cch / 3hex verification — regardless of what the upstream does downstream.

Usage:
    python3 capture_passthrough.py [--port 8788] [--upstream https://napi.origintask.cn]
"""
import argparse
import http.client
import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURED = os.path.join(HERE, "captured")
os.makedirs(CAPTURED, exist_ok=True)

# Hop-by-hop headers must not be forwarded (RFC 7230 §6.1).
HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
}

UPSTREAM = ("https", "napi.origintask.cn", 443)
COUNT = {"n": 0}


def _save(path, body, headers):
    ts = time.strftime("%Y%m%d-%H%M%S")
    n = COUNT["n"] = COUNT["n"] + 1
    base = os.path.join(CAPTURED, f"{ts}-{n:03d}")
    with open(base + ".bin", "wb") as f:
        f.write(body)
    with open(base + ".meta", "w") as f:
        f.write(f"size={len(body)}\n")
        f.write(f"path={path}\n")
        f.write(f"ua={headers.get('user-agent', '')}\n")
        f.write(f"anthropic-beta={headers.get('anthropic-beta', '')}\n")
        f.write(f"x-app={headers.get('x-app', '')}\n")
        # Stainless SDK / runtime versions — needed verbatim for
        # version_whitelist.go entries.
        f.write(f"x-stainless-package-version={headers.get('x-stainless-package-version', '')}\n")
        f.write(f"x-stainless-runtime-version={headers.get('x-stainless-runtime-version', '')}\n")
        f.write(f"x-stainless-runtime={headers.get('x-stainless-runtime', '')}\n")
    print(f"[capture] #{n} {len(body):>7} bytes  {path}  ua={headers.get('user-agent','')[:40]}",
          file=sys.stderr, flush=True)
    return base


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence default access log
        pass

    def _proxy(self, method):
        scheme, host, port = UPSTREAM
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else b""

        # Capture only the message-creation requests we care about.
        if "/v1/messages" in self.path and method == "POST" and body:
            self._inspect(body)

        # Forward verbatim.
        fwd_headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in HOP}
        fwd_headers["Host"] = host

        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=120)
        try:
            conn.request(method, self.path, body=body, headers=fwd_headers)
            resp = conn.getresponse()
            data = resp.read()
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"capture proxy upstream error: {e}".encode())
            print(f"[error] upstream: {e}", file=sys.stderr, flush=True)
            conn.close()
            return

        self.send_response(resp.status)
        for k, v in resp.getheaders():
            if k.lower() in HOP:
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    def _inspect(self, body):
        base = _save(self.path, body, self.headers)
        # Quick on-the-spot peek: does the body even carry a billing header?
        try:
            import json
            parsed = json.loads(body)
            sysblocks = parsed.get("system", [])
            billing = None
            if isinstance(sysblocks, list):
                for s in sysblocks:
                    if isinstance(s, dict) and "x-anthropic-billing-header:" in s.get("text", ""):
                        billing = s["text"]
                        break
            if billing:
                print(f"           billing: {billing[:120]}", file=sys.stderr, flush=True)
            else:
                print("           billing: <none in system[]>", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"           (peek failed: {e})", file=sys.stderr, flush=True)

    def do_POST(self):
        self._proxy("POST")

    def do_GET(self):
        self._proxy("GET")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8788)
    ap.add_argument("--upstream", default="https://napi.origintask.cn")
    args = ap.parse_args()

    global UPSTREAM
    u = urlsplit(args.upstream)
    UPSTREAM = (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80))

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"[ready] capture proxy on http://127.0.0.1:{args.port}  →  {args.upstream}",
          file=sys.stderr, flush=True)
    print(f"[ready] point the CLI at it:  ANTHROPIC_BASE_URL=http://127.0.0.1:{args.port}",
          file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[stop] shutting down", file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()
