// Package disguise — version whitelist for cch attestation compatibility.
//
// The cch ATTEST_KEYS in cch.go are extracted from a specific binary
// version range. ccproxy must only emit cc_version values whose binaries
// share those keys, otherwise our cch (computed with one set of keys)
// would not match what Anthropic's server expects (presumably keyed by
// the cc_version it sees on the wire).
//
// We therefore keep the (UserAgent, StainlessPackageVersion,
// StainlessRuntimeVersion) tuple under our control, never adopting the
// values reported by the live client. The client may run an arbitrary
// version (older, newer, third-party shim); we always rewrite to a
// version we have ground-truth-validated. This is intentionally
// stricter than "trust the wire": staying within a vetted set means
// every byte we emit has been observed in real Claude CLI traffic.
//
// Updating the whitelist:
//   1. Capture wire bytes from the new binary using cccc-mitm.
//   2. Run mitm-analysis/cch-probe/verify_captured.py to confirm cch +
//      3hex still validate with our existing ATTEST_KEYS.
//   3. If validation passes, append a new entry below.
//   4. If validation fails, ATTEST_KEYS rotated — extract new keys from
//      the binary first (see cch.go), then add the new tuple here.
//
// We never let an unvalidated version flow to upstream.
package disguise

// validatedTuple represents a complete CC client identity that has been
// observed on the wire AND verified to produce correct cch + 3hex with
// the current ATTEST_KEYS in cch.go. Every field is from a single
// observed real client — we never mix-and-match across releases.
type validatedTuple struct {
	UserAgent               string
	StainlessPackageVersion string
	StainlessRuntimeVersion string
	// CCHVariant selects the cch algorithm for this version. Zero value
	// (cchVariantKeyed4) applies to all pre-2.1.150 entries.
	CCHVariant cchVariant
}

// cchVariant selects which cch algorithm a CLI version uses. Claude Code
// rotated the algorithm between 2.1.150 and 2.1.185 — see cch.go (old,
// 4-key keyed-xxhash64 over the raw body) and cch_185.go (new, standard
// xxhash64 with seed=ATTEST_V3 over a normalized body). rewriteCCHInBody
// dispatches on the emitted tuple's variant.
type cchVariant int

const (
	// cchVariantKeyed4 is the pre-2.1.150 algorithm: xxhash64 with four
	// independent ATTEST_KEY lanes over the raw body. Zero value, so old
	// whitelist entries default to it without listing the field.
	cchVariantKeyed4 cchVariant = iota
	// cchVariantXXH64Norm is the 2.1.185+ algorithm: standard xxhash64
	// (seed=ATTEST_V3) over a body with model blanked and
	// max_tokens/fallbacks stripped. See cch_185.go.
	cchVariantXXH64Norm
)

// validatedTuples is the source of truth for what ccproxy is willing
// to advertise as its CLI identity. Ordered ascending by CLI version;
// we always pick the last (newest) entry for outbound traffic. Older
// entries are kept for documentation — they prove we tested across a
// range, and provide context if the newest entry ever needs to be
// rolled back.
//
// Keep entries in chronological order (oldest first). Each entry must
// have been verified against captured wire traffic — see file header.
var validatedTuples = []validatedTuple{
	{
		// Verified 2026-05-06 against capture.flow + fresh_sample.bin.
		// Same ATTEST_KEYS as 2.1.118, 2.1.126.
		UserAgent:               "claude-cli/2.1.114 (external, cli)",
		StainlessPackageVersion: "0.74.0",
		StainlessRuntimeVersion: "v22.13.0",
	},
	{
		// Verified 2026-05-06 by reverse-engineering the binary's JS
		// source; cch + 3hex algorithms reproduced byte-exact on
		// fresh_sample.bin (cch=58e37, 3hex=125).
		// Source: /Users/binn/.local/share/claude/versions/2.1.126
		UserAgent:               "claude-cli/2.1.126 (external, cli)",
		StainlessPackageVersion: "0.81.0",
		StainlessRuntimeVersion: "v24.3.0",
	},
	{
		// Verified 2026-05-07 against 58 captured cccc-mitm samples.
		// ATTEST_KEYS unchanged from 2.1.114/2.1.126 (proves the keys
		// continue to span at least 2.1.114 → 2.1.132). The binary
		// added one new isMeta wrapper prefix: "<local-command-stdout>"
		// (slash-command output appears as a meta user message); see
		// three_hex.go isMetaTextPrefixes.
		// SDK + Runtime versions unchanged from 2.1.126.
		UserAgent:               "claude-cli/2.1.132 (external, cli)",
		StainlessPackageVersion: "0.81.0",
		StainlessRuntimeVersion: "v24.3.0",
	},
	{
		// Verified 2026-05-11 against 24 captured cccc-mitm samples.
		// ATTEST_KEYS unchanged (V1..V4 at 0x039a49d0, byte-identical
		// to 2.1.132 — keys now span 2.1.114 → 2.1.138).
		// cch: 33/33 pass (100%). 3hex: not replicable from wire (known
		// systemic issue since 2.1.105, isMeta field absent on wire).
		// StainlessPackageVersion bumped 0.81.0 → 0.93.0; Runtime unchanged.
		// New beta: effort-2025-11-24 (already in beta.go BetaEffort const).
		UserAgent:               "claude-cli/2.1.138 (external, cli)",
		StainlessPackageVersion: "0.93.0",
		StainlessRuntimeVersion: "v24.3.0",
	},
	{
		// Verified 2026-05-25 against 17 captured cccc-mitm samples.
		// ATTEST_KEYS unchanged (keys now span 2.1.114 → 2.1.150, 36 versions).
		// cch: 17/17 pass (100%). 3hex: 17/17 pass (100%).
		// StainlessPackageVersion bumped 0.93.0 → 0.94.0; Runtime unchanged.
		// New betas observed: fast-mode-2026-02-01, structured-outputs-2025-12-15
		// (both already defined in beta.go).
		UserAgent:               "claude-cli/2.1.150 (external, cli)",
		StainlessPackageVersion: "0.94.0",
		StainlessRuntimeVersion: "v24.3.0",
	},
	{
		// Verified 2026-06-22 by reverse-engineering the 2.1.185 binary.
		// cch ALGORITHM ROTATED: standard xxhash64 (seed=ATTEST_V3) over a
		// normalized body (model blanked, max_tokens/fallbacks stripped),
		// replacing the old 4-key keyed-xxhash64. See cch_185.go +
		// mitm-analysis/cch-probe/FINDINGS-2.1.185.md appendix 7.
		// cch: reproduced byte-exact on 2 captured ground-truth bodies
		// (4eb53, a63f5) AND via live XXH64 hook on the running binary.
		// Stainless package/runtime UNCHANGED from 2.1.150 (0.94.0 /
		// v24.3.0, confirmed from captured x-stainless-* headers).
		// 3hex: unchanged (SHA256 salt "59cf53e54c78", see three_hex.go).
		UserAgent:               "claude-cli/2.1.185 (external, cli)",
		StainlessPackageVersion: "0.94.0",
		StainlessRuntimeVersion: "v24.3.0",
		CCHVariant:              cchVariantXXH64Norm,
	},
}

// latestValidatedTuple returns the most recently verified CC tuple. This
// is what gets emitted on every outbound request, regardless of what the
// live client advertised.
func latestValidatedTuple() validatedTuple {
	return validatedTuples[len(validatedTuples)-1]
}
