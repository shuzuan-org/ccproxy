"""Capture a single Claude Code request to verify cch with current ATTEST_KEYS (validated 2.1.114-2.1.138).

Run on port 8888, captures the first /v1/messages request body to fresh_sample.bin.
"""
import os
import sys
from mitmproxy import http

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fresh_sample.bin")
META = OUT + ".meta"
DONE = {"hit": False}


def request(flow: http.HTTPFlow):
    if DONE["hit"]:
        return
    if not flow.request.path.startswith("/v1/messages"):
        return
    if "anthropic.com" not in (flow.request.host or ""):
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
    DONE["hit"] = True
    print(f"[capture] saved {len(body)} bytes to {OUT}", file=sys.stderr)
