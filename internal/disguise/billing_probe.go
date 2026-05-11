package disguise

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/binn/ccproxy/internal/observe"
)

// BillingHeaderObserver passively records distribution data on Claude CLI's
// billing-header `cch` and `cc_version` 3hex suffixes from real client
// traffic. It is purely observational; the production path computes both
// values itself in cch.go (cch keyed-xxhash64) and three_hex.go (3hex
// vM3-style SHA256) and rewrites them on outbound requests.
//
// History — the prior cognitive model has been REVERSED.
//
// Until 2026-05 ccproxy operated under "the cch algorithm is unreachable
// from JS/Go" (Bun-native Zig stack, opaque from outside). The 3hex
// algorithm was likewise written off as "drifted" after CLI 2.1.105, with
// the observer's role limited to recording per-version mismatch counts so
// we wouldn't be tempted to re-engineer it.
//
// Reverse-engineering the 2.1.126 binary on 2026-05-06 invalidated both
// claims:
//
//   1. cch is keyed xxhash64 over the entire request body, with four
//      hardcoded 64-bit lane initial values (ATTEST_KEYS) extracted from
//      .rodata. ccproxy's Go implementation (see cch.go) reproduces the
//      algorithm byte-exact on captured traffic and is now the production
//      path's cch source.
//
//   2. The 3hex suffix is SHA256(salt + chars + version_triple)[:3] where
//      `chars` are bytes [4,7,20] of the first user message AFTER skipping
//      isMeta-flagged system injections. The "drift at 2.1.105" we observed
//      was the introduction of that isMeta filter; it can be reproduced
//      from wire-visible prefixes (see three_hex.go isMetaTextPrefixes).
//      ccproxy's 3hex is also now produced locally.
//
// Purpose under the new model:
//
//   The observer's job is no longer to "compare a known-wrong replica
//   against truth and log mismatches as the baseline". With cch.go and
//   three_hex.go in the production path, we DO have the truth — what the
//   observer surfaces is whether OUR algorithms still match the client's
//   on shared inputs. A persistent observed mismatch means one of:
//
//     - ATTEST_KEYS rotated → cch.go can no longer verify; bump
//       version_whitelist.go after extracting new keys
//     - isMetaTextPrefixes is missing a new injection prefix → 3hex
//       diverges; add the new prefix
//     - Whitelist drifted past where we have ground truth → time to
//       capture new wire samples and validate
//
// In other words the observer is now a passive canary for the
// version-whitelist maintenance loop documented in CLAUDE.md.
//
// What the observer is NOT:
//
//   - A trigger to bypass the whitelist. We never adopt observed
//     client values into outbound traffic; the response to "drift
//     detected" is a code change (whitelist update, key rotation,
//     prefix added), not a runtime adaptation.
//
//   - The cch/3hex calculator. That's cch.go and three_hex.go. The
//     observer keeps its own historical SHA256-replica function
//     (computeBillingFingerprintReplica below) only for the
//     comparison; do not import it into production code paths.
//
// Sampling: one entry per (UA_version, match_state) tuple. This gives a
// small stable set of log lines per real CLI version (match / mismatch /
// no_suffix) and is reset at process restart so post-upgrade re-observation
// just works.
//
// billingProbeSeenCap bounds the dedup map so an adversarial client cannot
// grow it without limit by rotating User-Agent versions. In steady state the
// map holds at most 3 entries per real CLI version (match / mismatch / no_suffix);
// the cap (1000) covers several hundred versions before the observer starts
// silently dropping — well past any realistic operational need.
const billingProbeSeenCap = 1000

// billingFingerprintSalt is the kM3 constant in the Claude CLI binary,
// used by both the historical observer-replica below AND the production
// 3hex computation in three_hex.go. Verified stable from 2.1.114 through
// 2.1.138; if Anthropic ever rotates it, both this observer and three_hex
// need updating in lockstep.
const (
	billingFingerprintSalt = "59cf53e54c78"
)

// billingFingerprintCharIndices are the byte positions of the first
// user message text used as input to the SHA256 hash. Stable across
// the entire whitelisted version range. Same caveat as the salt: if
// these ever change they must change in lockstep with three_hex.go.
var billingFingerprintCharIndices = [...]int{4, 7, 20}

// computeBillingFingerprintReplica reproduces the OLD pre-2.1.105 fingerprint
// algorithm — i.e. without the isMeta filter that three_hex.go now applies.
// Kept ONLY to feed the BillingHeaderObserver so it can flag per-version
// match/mismatch on legacy clients without dragging in the full vM3 logic.
//
// Production code MUST NOT call this. The current correct implementation
// is Compute3HexSuffix in three_hex.go.
func computeBillingFingerprintReplica(messageText, version string) string {
	var chars [len(billingFingerprintCharIndices)]byte
	for i, idx := range billingFingerprintCharIndices {
		if idx < len(messageText) {
			chars[i] = messageText[idx]
		} else {
			chars[i] = '0'
		}
	}
	var sb strings.Builder
	sb.Grow(len(billingFingerprintSalt) + len(chars) + len(version))
	sb.WriteString(billingFingerprintSalt)
	sb.Write(chars[:])
	sb.WriteString(version)
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])[:3]
}

// extractFirstUserMessageText returns the text content of the first message
// with role=user. Mirrors Claude Code's extractFirstUserMessageText:
//   - string content → return as-is
//   - array content → return the first {type:"text"} block's text
//   - anything else → return ""
func extractFirstUserMessageText(parsed map[string]interface{}) string {
	messages, ok := parsed["messages"].([]interface{})
	if !ok {
		return ""
	}
	for _, raw := range messages {
		m, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := m["role"].(string)
		if role != "user" {
			continue
		}
		switch content := m["content"].(type) {
		case string:
			return content
		case []interface{}:
			for _, b := range content {
				block, ok := b.(map[string]interface{})
				if !ok {
					continue
				}
				if t, _ := block["type"].(string); t == "text" {
					if text, ok := block["text"].(string); ok {
						return text
					}
				}
			}
		}
		// First user message consumed — don't look further.
		return ""
	}
	return ""
}

type BillingHeaderObserver struct {
	mu              sync.Mutex
	seen            map[string]struct{} // key: "<ua_version>|<state>"
	entrypointSeen  map[string]int      // key: "<ua_version>|<entrypoint>", value: cumulative hits
}

// NewBillingHeaderObserver returns an observer with fresh in-memory state.
func NewBillingHeaderObserver() *BillingHeaderObserver {
	return &BillingHeaderObserver{
		seen:           make(map[string]struct{}),
		entrypointSeen: make(map[string]int),
	}
}

// probeClientBillingRe captures the cc_version triple and optional suffix
// from a client-sent billing block. Only the first match is used; additional
// occurrences in the same block are ignored (real blocks carry one version).
var probeClientBillingRe = regexp.MustCompile(`cc_version=(\d+\.\d+\.\d+)(?:\.([A-Za-z0-9]{3}))?`)

// probeClientEntrypointRe captures the cc_entrypoint field from a client-sent
// billing block. Separate from the cc_version regex so the two extractions
// are independent — the source order is `cc_version=...; cc_entrypoint=...;`
// per claude-code:src/constants/system.ts:91, but we do not rely on it.
//
// Entrypoint values are allowed to contain alphanumerics and `-` (e.g.
// `sdk-cli`, `claude-code-github-action`, `claude-vscode`). See
// main.tsx:517-540 and main.tsx:818-833 in the reference claude-code source
// for the full enumeration of legal values.
var probeClientEntrypointRe = regexp.MustCompile(`cc_entrypoint=([A-Za-z0-9-]+)`)

// missingEntrypointSentinel is the bucket used when a billing block carries no
// cc_entrypoint field at all. Kept as a distinct key so analysts can tell
// "unobserved field" apart from a real legal value like "unknown" (which the
// upstream code emits when process.env.CLAUDE_CODE_ENTRYPOINT is unset —
// see claude-code:src/constants/system.ts:79).
const missingEntrypointSentinel = "<missing>"

// Observe inspects a single billing header block sent by a client and logs
// (at most once per UA_version/match pair) whether our algorithm replica
// still produces the same suffix.
//
// Inputs:
//   - ctx: request context for logger correlation. May be nil — in that case
//     a plain slog.Default() is used.
//   - uaVersion: the client's self-reported CLI version, extracted from the
//     incoming User-Agent header (NOT from our fingerprint store). Must be a
//     non-empty "X.Y.Z" string. Probing with the fingerprint UA would defeat
//     the purpose — we want to know what versions the wild is running.
//   - blockText: the RAW billing block text from the client body, before
//     syncBillingHeaderVersion has had a chance to rewrite it. If the block
//     doesn't contain a cc_version=... segment, this is a no-op.
//   - firstUserMessageText: the first user message's text content (may be
//     empty), used as the fingerprint algorithm's chars input. Byte-level
//     indexing (matches our implementation and auth2api's reference).
//
// The probe is a no-op when uaVersion is empty or blockText does not parse.
// Thread-safe.
func (p *BillingHeaderObserver) Observe(ctx context.Context, uaVersion, blockText, firstUserMessageText string) {
	if p == nil || uaVersion == "" || blockText == "" {
		return
	}

	// Extract the client's claimed cc_version and suffix from the block.
	sub := probeClientBillingRe.FindStringSubmatch(blockText)
	if sub == nil {
		return
	}
	clientVerTriple := sub[1]
	clientSuffix := ""
	if len(sub) > 2 {
		clientSuffix = sub[2]
	}
	// A missing suffix is itself a finding (modern CC clients always ship one)
	// — fall through and log it as a "no_suffix" state.

	// Recompute using our replica. The algorithm takes the cc_version triple
	// from the block (NOT the UA version) because that's what a real client
	// would have hashed: the block's version field is its own self-claim.
	expectedSuffix := computeBillingFingerprintReplica(firstUserMessageText, clientVerTriple)

	var state string
	switch {
	case clientSuffix == "":
		state = "no_suffix"
	case clientSuffix == expectedSuffix:
		state = "match"
	default:
		state = "mismatch"
	}

	logger := slog.Default()
	if ctx != nil {
		logger = observe.Logger(ctx)
	}

	// Independent second-dimension observation: record the cc_entrypoint
	// value that accompanied this block. This MUST run before the state
	// dedup early-return below — a single real CLI version may legitimately
	// appear with multiple entrypoints (interactive cli, sdk-cli, mcp, …)
	// over its lifetime, but the state dedup suppresses the whole log line
	// after the first hit. Keeping entrypoint recording independent lets
	// us observe the second dimension for already-seen states.
	//
	// See project_billing_cch_truth memory (2026-04-15 增补 §5) for the
	// full enumeration of legal cc_entrypoint values and why this field
	// is safe to observe structurally.
	p.recordEntrypoint(logger, uaVersion, clientVerTriple, blockText)

	// Dedup by (uaVersion, state). Once we've seen "2.1.88|match" we don't
	// need another; once we've seen "2.1.104|mismatch" the evidence is
	// already in the log and re-logging per request is noise.
	key := uaVersion + "|" + state
	p.mu.Lock()
	if _, already := p.seen[key]; already {
		p.mu.Unlock()
		return
	}
	// Hard cap: drop silently once the dedup map has grown past the cap.
	// New (uaVersion, state) tuples arriving after that point will neither
	// be logged nor remembered, which is preferable to unbounded growth
	// under a hostile client. Process restart clears the map.
	if len(p.seen) >= billingProbeSeenCap {
		p.mu.Unlock()
		return
	}
	p.seen[key] = struct{}{}
	p.mu.Unlock()

	// Build log attrs. Common to all states: UA version, client-claimed
	// cc_version triple, our expected suffix, the three char inputs (hex-
	// encoded so non-printable bytes show up), and a SHA256 digest of the
	// full first user message (16 hex chars is enough for correlation but
	// cannot reconstruct the text).
	charsHex := hexChars(firstUserMessageText, billingFingerprintCharIndices[:])
	msgDigest := shortDigest(firstUserMessageText)

	attrs := []any{
		"ua_version", uaVersion,
		"client_cc_version", clientVerTriple,
		"client_suffix", clientSuffix,
		"expected_suffix", expectedSuffix,
		"chars_hex", charsHex,
		"msg_len", len(firstUserMessageText),
		"msg_sha256_prefix", msgDigest,
		"state", state,
	}

	// For mismatch / no_suffix we also log the raw block text — these are
	// the states where someone will have to investigate, and the raw block
	// is the single most useful input. Match logs omit it to keep the noise
	// low (match is confirmation, not evidence).
	//
	// Severity note: as of cch-attestation rollout (2026-05) the production
	// path computes its own cch (cch.go) and 3hex (three_hex.go) and rewrites
	// them on outbound requests, so the probe is OBSERVATION ONLY. A
	// "mismatch" reported here does NOT mean the request being processed
	// is broken — Compute3HexSuffix runs the correct vM3-aware algorithm
	// and is unaffected by what this replica produces. The replica
	// intentionally lacks the isMeta filter so it can flag legacy clients
	// vs current clients on a single timeline. A persistent mismatch
	// pattern, paired with rising "no_suffix" counts on a particular UA
	// version, is the canary for "Anthropic shipped a new CLI we have
	// not whitelisted yet" — see CLAUDE.md "Maintaining the cch / 3hex
	// version whitelist" for the response procedure.
	if state == "mismatch" || state == "no_suffix" {
		attrs = append(attrs, "client_block", blockText)
		logger.Info("disguise: billing algo probe — client suffix differs from historical replica (observation only)", attrs...)
	} else {
		logger.Info("disguise: billing algo probe — client suffix matches replica", attrs...)
	}
}

// recordEntrypoint extracts cc_entrypoint from blockText and maintains a
// running counter of (uaVersion, entrypoint) combinations observed. First
// sighting of a new combination logs at INFO; subsequent sightings only
// increment the counter silently.
//
// A block with no cc_entrypoint field is bucketed under missingEntrypointSentinel
// so "field absent" stays distinct from the legal string value "unknown".
//
// Thread-safety: callers must NOT already hold p.mu — this method acquires
// it internally.
func (p *BillingHeaderObserver) recordEntrypoint(logger *slog.Logger, uaVersion, clientVerTriple, blockText string) {
	entrypoint := missingEntrypointSentinel
	if sub := probeClientEntrypointRe.FindStringSubmatch(blockText); sub != nil {
		entrypoint = sub[1]
	}

	key := uaVersion + "|" + entrypoint
	p.mu.Lock()
	hits, already := p.entrypointSeen[key]
	if already {
		p.entrypointSeen[key] = hits + 1
		p.mu.Unlock()
		return
	}
	// Apply the same cap as the state dedup map. Under normal operation
	// each real CLI version contributes at most ~5 distinct entrypoints
	// (cli/sdk-cli/mcp/local-agent/claude-vscode are the common ones), so
	// the cap comfortably covers hundreds of versions before rejecting.
	if len(p.entrypointSeen) >= billingProbeSeenCap {
		p.mu.Unlock()
		return
	}
	p.entrypointSeen[key] = 1
	// Snapshot so we log outside the lock (logger.Info may block on I/O).
	snapshot := len(p.entrypointSeen)
	p.mu.Unlock()

	logger.Info("disguise: billing entrypoint observation — new (cli_version, entrypoint) combination",
		"ua_version", uaVersion,
		"client_cc_version", clientVerTriple,
		"cc_entrypoint", entrypoint,
		"distinct_combinations_seen", snapshot,
	)
}

// hexChars encodes the bytes at the given indices of s into a hex string,
// using "00" for any index that's out of range. The output length is
// 2*len(indices). Matches the byte-level indexing used by
// computeBillingFingerprintReplica — if the real algorithm is rune-based
// or UTF-16 based (say, the client is JavaScript string-indexed), this
// function will record raw bytes for a human to compare.
func hexChars(s string, indices []int) string {
	buf := make([]byte, 0, 2*len(indices))
	for _, idx := range indices {
		var b byte
		if idx < len(s) {
			b = s[idx]
		}
		// 0x00 when out of range; note that computeBillingFingerprintReplica
		// uses '0' (0x30) for out-of-range, not 0x00. We intentionally record
		// 0x00 here so a reader can tell "OOR" apart from a literal '0' in
		// the real message.
		buf = append(buf, hexDigit(b>>4), hexDigit(b&0xf))
	}
	return string(buf)
}

func hexDigit(n byte) byte {
	if n < 10 {
		return '0' + n
	}
	return 'a' + (n - 10)
}

// shortDigest returns the first 16 hex chars of SHA256(s). Deterministic and
// non-reversible; used to correlate log entries for the same user message
// across multiple requests without storing the message itself.
func shortDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:16]
}

// ObserveParsedBody scans parsed["system"] for x-anthropic-billing-header
// blocks and calls Observe on each one. This is the high-level entry point
// used by the engine — it must be called BEFORE syncBillingHeaderVersion
// runs, otherwise the blocks it observes will already have been rewritten
// by our own code (making the "match" signal meaningless).
//
// uaVersion is the CLIENT's self-reported UA version, not our fingerprint
// UA. Pass extractUAVersion(origReq.Header.Get("User-Agent")).
func (p *BillingHeaderObserver) ObserveParsedBody(ctx context.Context, parsed map[string]interface{}, uaVersion string) {
	if p == nil || uaVersion == "" || parsed == nil {
		return
	}
	msgText := extractFirstUserMessageText(parsed)

	visit := func(text string) {
		if !strings.HasPrefix(strings.TrimSpace(text), billingHeaderPrefix) {
			return
		}
		p.Observe(ctx, uaVersion, text, msgText)
	}

	switch v := parsed["system"].(type) {
	case string:
		visit(v)
	case []interface{}:
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			text, _ := m["text"].(string)
			if text != "" {
				visit(text)
			}
		}
	}
}
