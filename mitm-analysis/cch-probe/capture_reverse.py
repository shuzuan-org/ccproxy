"""Reverse-proxy capture: catch any /v1/messages request body to fresh_sample.bin."""
import os
import sys
from mitmproxy import http

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fresh_sample.bin")
META = OUT + ".meta"
DONE = {"hit": False}


def request(flow: http.HTTPFlow):
    if DONE["hit"]:
        return
    if "/v1/messages" not in flow.request.path:
        return
    body = flow.request.raw_content or b""
    if not body:
        return
    with open(OUT, "wb") as f:
        f.write(body)
    with open(META, "w") as f:
        f.write(f"size={len(body)}\n")
        f.write(f"ua={flow.request.headers.get('user-agent','')}\n")
        f.write(f"host={flow.request.host}\n")
        f.write(f"path={flow.request.path}\n")
        f.write(f"x_app={flow.request.headers.get('x-app','')}\n")
        f.write(f"anthropic_beta={flow.request.headers.get('anthropic-beta','')}\n")
    DONE["hit"] = True
    print(f"[capture] saved {len(body)} bytes to {OUT}", file=sys.stderr)
