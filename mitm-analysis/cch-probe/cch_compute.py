"""cch_compute.py — Reference implementation of Claude Code's cch attestation.

Algorithm: keyed xxhash64 with hardcoded v1..v4 init values (not seed-derived).
Output: lower 20 bits formatted as 5 lowercase hex chars.

Verified against Claude Code 2.1.114 - 2.1.138 (same ATTEST_KEYS across all
24 releases; binary diff at .rodata 0x039a49d0).
"""
import struct

PRIME64_1 = 0x9E3779B185EBCA87
PRIME64_2 = 0xC2B2AE3D27D4EB4F
PRIME64_3 = 0x165667B19E3779F9
PRIME64_4 = 0x85EBCA77C2B2AE63
PRIME64_5 = 0x27D4EB2F165667C5
MASK64 = (1 << 64) - 1

ATTEST_V1 = 0xAE4FBA0790EAE83E
ATTEST_V2 = 0x101840560AFF1DB7
ATTEST_V3 = 0x4D659218E32A3268
ATTEST_V4 = 0xAF2E18675D3E67E1


def rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & MASK64


def _round(state, lane_in):
    state = (state + lane_in * PRIME64_2) & MASK64
    state = rotl64(state, 31)
    return (state * PRIME64_1) & MASK64


def _merge_round(acc, val):
    val = _round(0, val)
    acc ^= val
    return (acc * PRIME64_1 + PRIME64_4) & MASK64


def xxhash64_keyed(body: bytes,
                   v1=ATTEST_V1, v2=ATTEST_V2, v3=ATTEST_V3, v4=ATTEST_V4) -> int:
    n, i = len(body), 0
    if n >= 32:
        while i + 32 <= n:
            v1 = _round(v1, struct.unpack_from("<Q", body, i)[0])
            v2 = _round(v2, struct.unpack_from("<Q", body, i + 8)[0])
            v3 = _round(v3, struct.unpack_from("<Q", body, i + 16)[0])
            v4 = _round(v4, struct.unpack_from("<Q", body, i + 24)[0])
            i += 32
        h = (rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18)) & MASK64
        h = _merge_round(h, v1)
        h = _merge_round(h, v2)
        h = _merge_round(h, v3)
        h = _merge_round(h, v4)
    else:
        h = (v3 + PRIME64_5) & MASK64
    h = (h + n) & MASK64
    while i + 8 <= n:
        k = struct.unpack_from("<Q", body, i)[0]
        k = _round(0, k)
        h ^= k
        h = (rotl64(h, 27) * PRIME64_1 + PRIME64_4) & MASK64
        i += 8
    while i + 4 <= n:
        k = struct.unpack_from("<I", body, i)[0]
        h ^= (k * PRIME64_1) & MASK64
        h = (rotl64(h, 23) * PRIME64_2 + PRIME64_3) & MASK64
        i += 4
    while i < n:
        h ^= (body[i] * PRIME64_5) & MASK64
        h = (rotl64(h, 11) * PRIME64_1) & MASK64
        i += 1
    h ^= h >> 33
    h = (h * PRIME64_2) & MASK64
    h ^= h >> 29
    h = (h * PRIME64_3) & MASK64
    h ^= h >> 32
    return h


def cch_token(body: bytes) -> str:
    return f"{xxhash64_keyed(body) & 0xFFFFF:05x}"


# ---------- Self-test: standard xxhash64 with seed=0 ----------
def xxhash64_seed(body: bytes, seed: int = 0) -> int:
    v1 = (seed + PRIME64_1 + PRIME64_2) & MASK64
    v2 = (seed + PRIME64_2) & MASK64
    v3 = seed
    v4 = (seed - PRIME64_1) & MASK64
    return xxhash64_keyed(body, v1, v2, v3, v4)


if __name__ == "__main__":
    print("Test 1: standard xxhash64 (seed=0) sanity check")
    expected = {
        b"": 0xef46db3751d8e999,
        b"abc": 0x44bc2cf5ad770999,
        b"a" * 32: 0x856e843298f99ad7,
        b"hello world": 0x45ab6734b21e6968,
    }
    all_ok = True
    for inp, exp in expected.items():
        got = xxhash64_seed(inp)
        ok = got == exp
        all_ok &= ok
        mark = "OK" if ok else "FAIL"
        print(f"  [{mark}] xxhash64({inp!r:20}) = 0x{got:016x}  expected 0x{exp:016x}")
    print(f"  => standard xxhash64 implementation is {'CORRECT' if all_ok else 'BROKEN'}")
