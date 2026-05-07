"""Continuous reverse-proxy capture: store every /v1/messages request to captured/.

Stores one .bin per request (raw body) + one .meta per request (headers + cc_version + cch).
Files named by timestamp + short hash so they can pile up across runs.
"""
import os
import sys
import time
import json
import re
import hashlib
from mitmproxy import http

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captured")
os.makedirs(OUT_DIR, exist_ok=True)

# Match billing-header fields ONLY inside the system block — not anywhere
# in the body — because user prompts can legitimately contain "cch=..."
# substrings (e.g. when discussing this code).
BILLING_LINE_RE = re.compile(r"x-anthropic-billing-header:[^\"\\]+")
CCH_RE = re.compile(r"cch=([0-9a-f]{5})")
CC_VERSION_RE = re.compile(r"cc_version=(\d+\.\d+\.\d+)\.([0-9a-f]{3})")


def extract_billing_text(body: bytes) -> str | None:
    """Find the x-anthropic-billing-header text inside parsed.system, ignoring
    any occurrences inside user-authored content."""
    try:
        parsed = json.loads(body)
    except Exception:
        return None
    s = parsed.get("system")
    if isinstance(s, str):
        if "x-anthropic-billing-header" in s:
            return s
        return None
    if isinstance(s, list):
        for item in s:
            if isinstance(item, dict):
                t = item.get("text", "")
                if isinstance(t, str) and t.startswith("x-anthropic-billing-header"):
                    return t
    return None


def request(flow: http.HTTPFlow):
    if "/v1/messages" not in flow.request.path:
        return
    body = flow.request.raw_content or b""
    if not body:
        return

    ts = time.strftime("%Y%m%d-%H%M%S")
    short = hashlib.sha1(body).hexdigest()[:8]
    base = os.path.join(OUT_DIR, f"{ts}-{short}")

    with open(base + ".bin", "wb") as f:
        f.write(body)

    billing = extract_billing_text(body) or ""
    cch_m = CCH_RE.search(billing)
    cv_m = CC_VERSION_RE.search(billing)
    with open(base + ".meta", "w") as f:
        f.write(f"size={len(body)}\n")
        f.write(f"ua={flow.request.headers.get('user-agent','')}\n")
        f.write(f"host={flow.request.host}\n")
        f.write(f"path={flow.request.path}\n")
        f.write(f"x_app={flow.request.headers.get('x-app','')}\n")
        f.write(f"anthropic_beta={flow.request.headers.get('anthropic-beta','')}\n")
        f.write(f"x_stainless_package_version={flow.request.headers.get('x-stainless-package-version','')}\n")
        f.write(f"x_stainless_runtime_version={flow.request.headers.get('x-stainless-runtime-version','')}\n")
        f.write(f"x_stainless_os={flow.request.headers.get('x-stainless-os','')}\n")
        f.write(f"x_stainless_arch={flow.request.headers.get('x-stainless-arch','')}\n")
        f.write(f"x_stainless_runtime={flow.request.headers.get('x-stainless-runtime','')}\n")
        f.write(f"cch={cch_m.group(1) if cch_m else '<none>'}\n")
        if cv_m:
            f.write(f"cc_version_triple={cv_m.group(1)}\n")
            f.write(f"cc_version_3hex={cv_m.group(2)}\n")

    print(f"[capture] {ts}-{short} size={len(body)} cch={cch_m.group(1) if cch_m else '?'} 3hex={cv_m.group(2) if cv_m else '?'}", file=sys.stderr)
