// Package disguise — cch attestation hash, 2.1.185+ variant.
//
// Claude Code rotated the cch algorithm sometime between 2.1.150 and
// 2.1.185. The new scheme is STANDARD xxhash64 (seed-derived lanes, not
// the four independent ATTEST_KEY lanes used by the pre-2.1.150 algorithm
// in cch.go) keyed by a single seed, computed over a NORMALIZED copy of
// the request body rather than the raw wire body.
//
//	cch = lower5hex( XXH64(normalize(body), seed=ATTEST_V3) & 0xFFFFF )
//
// where ATTEST_V3 = 0x4D659218E32A3268 (the same constant that was lane
// v3 of the old 4-key algorithm — Anthropic kept it and dropped V1/V2/V4).
//
// normalize(body) is the wire body JSON with these edits applied to the
// HASH INPUT ONLY (the bytes actually transmitted keep their real values):
//
//  1. "model":"<value>"      -> "model":""        (model value blanked)
//  2. ,"max_tokens":<number>  removed              (volatile routing param)
//  3. ,"fallbacks":[...]       removed              (volatile routing param)
//  4. cch=XXXXX;             -> cch=00000;         (placeholder; already
//     in place when rewriteCCHInBody runs, so normally a no-op here)
//
// Reverse-engineered and verified 2026-06-22 against Claude Code 2.1.185
// (binary /Users/david/.local/share/claude/versions/2.1.185):
//
//   - XXH64_reset @ 0x1005feabc — confirmed standard xxhash64 accumulator
//     init: v1=seed+P1+P2, v2=seed+P2, v3=seed, v4=seed-P1 (the four add
//     constants in the binary are exactly 0x60EA27EEADC0B5D6 = P1+P2,
//     0xC2B2AE3D27D4EB4F = P2, 0, 0x61C8864E7A143579 = -P1).
//   - XXH64_update @ 0x1005feb20, orchestrator @ 0x101424bac, body field
//     parser (searches "model":/"fallbacks":[/"max_tokens":) @ 0x10142ca80.
//   - Verified by hooking XXH64_reset (filtered on seed=ATTEST_V3) +
//     XXH64_update to capture the exact input bytes: live cch matched
//     (low20 of XXH64(captured input) == observed cch).
//   - Verified offline against two independent captured ground-truth
//     bodies: 4eb53 and a63f5 reproduced byte-exact (see cch_185_test.go
//     and mitm-analysis/cch-probe/FINDINGS-2.1.185.md appendix 7).
//
// The seed is a baked key and may rotate again in a future release. To
// re-extract: search the binary for the xxhash64 accumulator init pattern
// (a constant equal to PRIME64_1+PRIME64_2 = 0x60EA27EEADC0B5D6 added to
// a register) — the register holds the seed. See FINDINGS-2.1.185.md
// "破解方法论" for the full procedure.
package disguise

import (
	"fmt"
	"regexp"
)

// cchSeed185 is the xxhash64 seed for the 2.1.185+ cch algorithm. It is
// the surviving member (V3) of the old 4-key ATTEST set. Defined in terms
// of attestV3 (cch.go) so the two never drift.
const cchSeed185 = attestV3

var (
	// cchModelRe matches the top-level "model":"..." field. The body
	// always begins `{"model":"..."` so the first match is the top-level
	// one; we replace only the first.
	cchModelRe = regexp.MustCompile(`"model":"[^"]*"`)
	// cchMaxTokensRe matches a top-level ,"max_tokens":<number> field
	// (with its leading comma). Tool/schema occurrences use
	// `"max_tokens":{...}` and so do not match `:\d+`.
	cchMaxTokensRe = regexp.MustCompile(`,?"max_tokens":\d+`)
	// cchFallbacksRe matches a ,"fallbacks":[...] array field. Unverified
	// against ground truth (captured bodies had no fallbacks) but the
	// native parser searches for `"fallbacks":[`, so we mirror it.
	cchFallbacksRe = regexp.MustCompile(`,?"fallbacks":\[[^\]]*\]`)
)

// normalizeBodyForCCH185 returns the hash input for the 2.1.185 cch: a
// copy of body with model blanked and max_tokens/fallbacks stripped. The
// input body is not mutated. Each edit replaces only the first match,
// matching the native parser which operates on the single top-level field.
func normalizeBodyForCCH185(body []byte) []byte {
	out := replaceFirst(cchModelRe, body, []byte(`"model":""`))
	out = replaceFirst(cchMaxTokensRe, out, nil)
	out = replaceFirst(cchFallbacksRe, out, nil)
	return out
}

// ComputeCCH185 returns the 5-hex cch token for the 2.1.185+ algorithm.
//
// As with ComputeCCH (the old algorithm), body MUST already contain the
// "cch=00000;" placeholder — the placeholder participates in the hash and
// is overwritten in place afterwards by rewriteCCHInBody.
func ComputeCCH185(body []byte) string {
	norm := normalizeBodyForCCH185(body)
	// Standard xxhash64 with seed: lanes are seed-derived. This is exactly
	// what XXH64_reset @ 0x1005feabc does. Reuse xxhash64Keyed (cch.go) so
	// there is a single hash implementation. seed is a runtime uint64 so
	// the lane arithmetic wraps mod 2^64 (Go rejects const overflow).
	seed := uint64(cchSeed185)
	v1 := seed + prime64_1 + prime64_2
	v2 := seed + prime64_2
	v3 := seed
	v4 := seed - prime64_1
	h := xxhash64Keyed(norm, v1, v2, v3, v4)
	return fmt.Sprintf("%05x", h&0xFFFFF)
}

// replaceFirst replaces the first match of re in src with repl, returning
// a new slice (src is not modified). Returns src unchanged when there is
// no match. A nil repl deletes the match.
func replaceFirst(re *regexp.Regexp, src, repl []byte) []byte {
	loc := re.FindIndex(src)
	if loc == nil {
		return src
	}
	out := make([]byte, 0, len(src)-(loc[1]-loc[0])+len(repl))
	out = append(out, src[:loc[0]]...)
	out = append(out, repl...)
	out = append(out, src[loc[1]:]...)
	return out
}
