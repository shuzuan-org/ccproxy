"""extract_cch_samples.py — Run with mitmdump to extract Claude Code request samples.

Usage:
    /opt/homebrew/bin/mitmdump -nr capture.flow -s extract_cch_samples.py

Outputs samples/<idx>.bin (raw body) and samples/index.tsv (idx, size, cch, ua, host).
"""
import os
import re
from mitmproxy import http
from mitmproxy import io as mitm_io

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
INDEX_PATH = os.path.join(OUT_DIR, "index.tsv")
os.makedirs(OUT_DIR, exist_ok=True)

CCH_RE = re.compile(rb"cch=([0-9a-f]{5})")
COUNTER = {"n": 0, "kept": 0}


def request(flow: http.HTTPFlow):
    COUNTER["n"] += 1
    if not flow.request.path.startswith("/v1/messages"):
        return
    if "anthropic.com" not in (flow.request.host or ""):
        return
    body = flow.request.raw_content
    if not body:
        return
    m = CCH_RE.search(body)
    if not m:
        return
    cch = m.group(1).decode()
    idx = COUNTER["kept"]
    COUNTER["kept"] += 1
    with open(os.path.join(OUT_DIR, f"{idx:04d}.bin"), "wb") as f:
        f.write(body)
    ua = flow.request.headers.get("user-agent", "")
    host = flow.request.host
    with open(INDEX_PATH, "a") as f:
        f.write(f"{idx}\t{len(body)}\t{cch}\t{ua}\t{host}\n")


def done():
    print(f"Processed {COUNTER['n']} flows, kept {COUNTER['kept']} with cch")
