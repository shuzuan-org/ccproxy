#!/usr/bin/env python3
"""cch 算法 (Claude Code 2.1.185) — 完全逆向 + 双样本验证通过 (2026-06-22)

cch = XXH64(normalized_body, seed=0x4d659218e32a3268) & 0xFFFFF, 格式化为 5 位小写 hex

normalized_body = wire 请求体 JSON,做以下规范化:
  1. "model":"..."  -> "model":""       (model 值置空)
  2. 删除 max_tokens 字段 (含其逗号)
  3. 删除 fallbacks 字段 (若存在)
  4. cch=XXXXX;     -> cch=00000;        (占位符——hash 在回填前计算)

native 函数 (binary 2.1.185, module base 0x100000000):
  - XXH64_reset(state, seed)  @ 0x1005feabc   (init: v1=seed+P1+P2, v2=seed+P2, v3=seed, v4=seed-P1)
  - XXH64_update(state,p,len) @ 0x1005feb20
  - cch 编排器 (提取/规范化 body + XXH64) @ 0x101424bac
  - body JSON 字段解析器 @ 0x10142ca80
  seed 0x4d659218e32a3268 = 旧 ATTEST_V3 (单 key,非旧版 4-key keyed-xxhash64)
"""
import re
import xxhash

CCH_SEED = 0x4d659218e32a3268

def normalize_body(raw: bytes) -> bytes:
    s = raw
    s = re.sub(rb'"model":"[^"]*"', b'"model":""', s, count=1)
    s = re.sub(rb'cch=[0-9a-f]{5};', b'cch=00000;', s, count=1)
    s = re.sub(rb',?"max_tokens":\d+', b'', s, count=1)
    s = re.sub(rb',?"fallbacks":\[[^\]]*\]', b'', s, count=1)
    return s

def compute_cch(raw: bytes) -> str:
    h = xxhash.xxh64(normalize_body(raw), seed=CCH_SEED).intdigest()
    return '%05x' % (h & 0xFFFFF)

if __name__ == '__main__':
    import sys
    for fn, tgt in [('captured/20260622-015610-063.pre','4eb53'),
                    ('captured/20260622-015610-064.pre','a63f5')]:
        try:
            got = compute_cch(open(fn,'rb').read())
            print('%s: cch=%s target=%s %s' % (fn.split('/')[-1], got, tgt, 'OK' if got==tgt else 'FAIL'))
        except FileNotFoundError:
            print('%s: (missing)' % fn)
