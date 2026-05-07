// Package disguise — cch attestation hash.
//
// cch = lower5hex( xxhash64_keyed(body, ATTEST_V1..V4) & 0xFFFFF )
//
// The Bun-native layer of the official Claude CLI computes this 5-hex token
// and writes it into the request body's billing header text. It is keyed
// xxhash64: the 5 PRIME64 constants are the standard xxhash64 primes, but
// the four lane initialization values v1..v4 are hardcoded ATTEST_KEYS
// rather than seed-derived. Confirmed identical across Claude Code 2.1.114
// — 2.1.126 (extracted from the binary's .rodata; V1..V4 are 32 contiguous
// bytes that occur exactly once each).
//
// Standard `cespare/xxhash` cannot be used because it does not expose a way
// to override v1..v4. The implementation here follows the standard xxhash64
// stream layout — main loop on 32-byte chunks, then 8/4/1-byte tails, then
// avalanche — with the only deviation being how lanes start.
//
// Extracting ATTEST_KEYS from a new Claude Code binary
//
// When verify_captured.py reports cch failures (cch.go computes the wrong
// value despite the algorithm being correct), the keys have rotated. To
// recover them:
//
//	# 1. Find ATTEST_V1 in the new binary by grepping the OLD V1 first to
//	#    confirm it is gone, then search for "4 contiguous u64 values"
//	#    near the .rodata segment. The current V1 little-endian byte
//	#    sequence is "3e e8 ea 90 07 ba 4f ae" — its uniqueness in the
//	#    binary is what makes extraction reliable.
//	python3 -c '
//	import struct
//	with open("/path/to/new/claude-binary","rb") as f: data = f.read()
//	old_v1 = bytes.fromhex("3ee8ea9007ba4fae")
//	pos = data.find(old_v1)
//	if pos != -1:
//	    print(f"Old V1 still present at 0x{pos:08x} — keys did not rotate")
//	else:
//	    print("Old V1 missing — keys rotated. Disassemble around the cch")
//	    print("function call sites (search for cch=00000 string xrefs)")
//	    print("to locate the new 4×u64 table.")
//	'
//
// Once the new V1..V4 are known, update the four constants below and add
// the new CLI version to validatedTuples in version_whitelist.go. See
// CLAUDE.md "Maintaining the cch / 3hex version whitelist" for the full
// procedure.
package disguise

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

const (
	prime64_1 uint64 = 0x9E3779B185EBCA87
	prime64_2 uint64 = 0xC2B2AE3D27D4EB4F
	prime64_3 uint64 = 0x165667B19E3779F9
	prime64_4 uint64 = 0x85EBCA77C2B2AE63
	prime64_5 uint64 = 0x27D4EB2F165667C5

	attestV1 uint64 = 0xAE4FBA0790EAE83E
	attestV2 uint64 = 0x101840560AFF1DB7
	attestV3 uint64 = 0x4D659218E32A3268
	attestV4 uint64 = 0xAF2E18675D3E67E1
)

func xxhRound(state, lane uint64) uint64 {
	state += lane * prime64_2
	state = bits.RotateLeft64(state, 31)
	state *= prime64_1
	return state
}

func xxhMergeRound(acc, val uint64) uint64 {
	val = xxhRound(0, val)
	acc ^= val
	return acc*prime64_1 + prime64_4
}

// xxhash64Keyed computes xxhash64 with caller-provided lane initial values
// instead of seed-derived ones. Used by ComputeCCH with the ATTEST_KEYS.
func xxhash64Keyed(body []byte, v1, v2, v3, v4 uint64) uint64 {
	n := len(body)
	i := 0
	var h uint64

	if n >= 32 {
		for i+32 <= n {
			v1 = xxhRound(v1, binary.LittleEndian.Uint64(body[i:]))
			v2 = xxhRound(v2, binary.LittleEndian.Uint64(body[i+8:]))
			v3 = xxhRound(v3, binary.LittleEndian.Uint64(body[i+16:]))
			v4 = xxhRound(v4, binary.LittleEndian.Uint64(body[i+24:]))
			i += 32
		}
		h = bits.RotateLeft64(v1, 1) +
			bits.RotateLeft64(v2, 7) +
			bits.RotateLeft64(v3, 12) +
			bits.RotateLeft64(v4, 18)
		h = xxhMergeRound(h, v1)
		h = xxhMergeRound(h, v2)
		h = xxhMergeRound(h, v3)
		h = xxhMergeRound(h, v4)
	} else {
		h = v3 + prime64_5
	}
	h += uint64(n)

	for i+8 <= n {
		k := binary.LittleEndian.Uint64(body[i:])
		k = xxhRound(0, k)
		h ^= k
		h = bits.RotateLeft64(h, 27)*prime64_1 + prime64_4
		i += 8
	}
	for i+4 <= n {
		k := uint64(binary.LittleEndian.Uint32(body[i:]))
		h ^= k * prime64_1
		h = bits.RotateLeft64(h, 23)*prime64_2 + prime64_3
		i += 4
	}
	for i < n {
		h ^= uint64(body[i]) * prime64_5
		h = bits.RotateLeft64(h, 11) * prime64_1
		i++
	}

	h ^= h >> 33
	h *= prime64_2
	h ^= h >> 29
	h *= prime64_3
	h ^= h >> 32
	return h
}

// ComputeCCH returns the 5-hex cch token for the given request body bytes.
//
// The body MUST already contain the "cch=00000;" placeholder at the position
// where the final value will be written. The hash input is the body with
// the placeholder still in place — see the call-site contract in
// rewriteCCHInBody.
func ComputeCCH(body []byte) string {
	h := xxhash64Keyed(body, attestV1, attestV2, attestV3, attestV4)
	return fmt.Sprintf("%05x", h&0xFFFFF)
}

// cchPlaceholder is what billing header injection writes; cch must be
// computed with this placeholder still present in the body, then the 5
// '0' chars are overwritten in place with the real cch.
const cchPlaceholder = "cch=00000"

// rewriteCCHInBody finds the cch=00000 placeholder in body, computes cch
// over the body (with placeholder present), and overwrites the 5 zero
// chars with the result. Returns true if a placeholder was found and
// rewritten. Idempotent only when the placeholder is still "00000" —
// running twice on a body that already has a real cch would produce a
// different hash (because the wire-version 5 chars participate in the
// hash) and break self-consistency.
//
// Mutates body in place; the byte length is unchanged.
func rewriteCCHInBody(body []byte) bool {
	idx := indexOf(body, []byte(cchPlaceholder))
	if idx < 0 {
		return false
	}
	cch := ComputeCCH(body)
	// Overwrite exactly 5 chars at idx+4 .. idx+9 (the "00000").
	copy(body[idx+4:idx+9], cch)
	return true
}

func indexOf(haystack, needle []byte) int {
	hlen, nlen := len(haystack), len(needle)
	if nlen == 0 || nlen > hlen {
		return -1
	}
	first := needle[0]
	for i := 0; i <= hlen-nlen; i++ {
		if haystack[i] != first {
			continue
		}
		match := true
		for j := 1; j < nlen; j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
