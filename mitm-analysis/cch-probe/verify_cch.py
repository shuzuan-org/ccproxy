"""verify_cch.py — Validate cch_compute against real samples extracted from capture.flow."""
import os
import re
import sys
from cch_compute import xxhash64_keyed, cch_token

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
INDEX_PATH = os.path.join(SAMPLES_DIR, "index.tsv")
PLACEHOLDER = b"cch=00000"
CCH_RE = re.compile(rb"cch=([0-9a-f]{5})")


def reconstruct_pre_hash_body(body: bytes, observed_cch: str) -> bytes:
    """Replace observed cch back to placeholder so we hash what was hashed pre-write."""
    needle = f"cch={observed_cch}".encode()
    return body.replace(needle, PLACEHOLDER, 1)


def main():
    with open(INDEX_PATH) as f:
        rows = [line.rstrip("\n").split("\t") for line in f if line.strip()]

    total = 0
    ok = 0
    fails = []
    by_version = {}

    for idx, size, cch, ua, host in rows:
        path = os.path.join(SAMPLES_DIR, f"{int(idx):04d}.bin")
        with open(path, "rb") as f:
            body = f.read()
        # Check there's exactly one cch occurrence (no ambiguity)
        matches = CCH_RE.findall(body)
        if len(matches) != 1 or matches[0].decode() != cch:
            fails.append((idx, "ambiguous cch in body"))
            continue
        pre_body = reconstruct_pre_hash_body(body, cch)
        computed = cch_token(pre_body)
        total += 1
        ver_key = re.search(r"claude-cli/(\d+\.\d+\.\d+)", ua)
        ver = ver_key.group(1) if ver_key else "?"
        by_version.setdefault(ver, [0, 0])
        by_version[ver][0] += 1
        if computed == cch:
            ok += 1
            by_version[ver][1] += 1
        else:
            fails.append((idx, f"v{ver} computed={computed} expected={cch} size={size}"))

    print(f"Total: {total}, OK: {ok}, FAIL: {total - ok}")
    print("\nBy version:")
    for ver, (n, k) in sorted(by_version.items()):
        print(f"  {ver}: {k}/{n} OK")
    if fails:
        print(f"\nFirst {min(10, len(fails))} failures:")
        for idx, reason in fails[:10]:
            print(f"  sample #{idx}: {reason}")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
