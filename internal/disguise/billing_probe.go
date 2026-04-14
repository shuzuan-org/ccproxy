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

// BillingHeaderObserver passively records the distribution of Claude CLI's
// billing-header `cch` suffix values across real client traffic, by
// comparing each observed suffix against a historical SHA256-based replica
// that we know is NOT the true algorithm.
//
// The true algorithm, per claude-code:src/constants/system.ts:73-94, is
// implemented in Bun's native Zig HTTP stack (bun-anthropic Attestation.zig)
// under the NATIVE_CLIENT_ATTESTATION feature flag. The stack writes a
// `cch=00000` placeholder into the serialized request body and overwrites
// the zeros in place after serialization. This means:
//
//   1. The algorithm is not reachable from JS/Go — any JS-layer replica is
//      guaranteed to diverge from real client values on at least some
//      inputs. The observation "mismatch" state is EXPECTED, not a sign
//      that the algorithm has "drifted" or "upgraded".
//
//   2. ccproxy's v0.1.11 SHA256 replica (salt "59cf53e54c78", indices
//      [4,7,20]) was cross-referenced against auth2api's implementation,
//      which itself was derived from mitmproxy captures. The captures
//      happened to line up with SHA256 for a narrow window of messages,
//      producing the illusion of a pure JS-computable algorithm. v0.1.12
//      removed the replica from the production path after this observer
//      began recording mismatches on Claude CLI 2.1.105+.
//
// Purpose (unchanged since v0.1.12): this observer is OBSERVATION-ONLY.
// It logs at INFO level and never mutates outbound requests. Its value is:
//
//   - Surface real cch values from production traffic so we can, if we
//     ever need to, analyze their distribution offline and look for
//     structural patterns (byte layout, length variations, version
//     coupling, etc.).
//   - Detect regressions where a future ccproxy change accidentally
//     couples business logic to the replica. A production effect would
//     show up as "our own requests show match while client requests show
//     mismatch" — a canary only this observer can provide.
//   - Provide cheap ground truth for "is this CLI version still emitting
//     cch at all?" without pulling in a real Claude CLI client.
//
// It is NOT:
//
//   - A drift detector. We already know the JS replica does not match
//     the true algorithm; logging mismatch is confirming the baseline,
//     not discovering new information.
//   - A trigger for re-reverse-engineering the algorithm. See the
//     project_billing_cch_truth memory for why "one more capture round"
//     will not produce a correct replica.
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

// Historical replica constants. These reflect the algorithm Claude CLI used
// circa 2.1.88. Used by the probe to detect drift and by nothing else.
const (
	billingFingerprintSalt = "59cf53e54c78"
)

var billingFingerprintCharIndices = [...]int{4, 7, 20}

// computeBillingFingerprintReplica reproduces the historical Claude CLI
// fingerprint algorithm circa 2.1.88:
//
//	SHA256(SALT + msg[4] + msg[7] + msg[20] + version).hex()[:3]
//
// where msg is the first user message's text (or "0" for any out-of-range
// index, byte-indexed). Returns lowercase 3-hex-char output.
//
// This is no longer used to mutate outbound traffic — it lives here purely
// so the probe can compare it against client-sent suffixes and surface
// drift. If the real algorithm changes, the only consequence is more
// "mismatch" log lines until the probe is updated to a new replica.
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
	mu   sync.Mutex
	seen map[string]struct{} // key: "<ua_version>|<state>"
}

// NewBillingHeaderObserver returns an observer with fresh in-memory state.
func NewBillingHeaderObserver() *BillingHeaderObserver {
	return &BillingHeaderObserver{
		seen: make(map[string]struct{}),
	}
}

// probeClientBillingRe captures the cc_version triple and optional suffix
// from a client-sent billing block. Only the first match is used; additional
// occurrences in the same block are ignored (real blocks carry one version).
var probeClientBillingRe = regexp.MustCompile(`cc_version=(\d+\.\d+\.\d+)(?:\.([A-Za-z0-9]{3}))?`)

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

	logger := slog.Default()
	if ctx != nil {
		logger = observe.Logger(ctx)
	}

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
	// the states where someone will have to reverse engineer the real
	// algorithm, and the raw block is the single most useful input. Match
	// logs omit it to keep the noise low (match is confirmation, not
	// evidence).
	//
	// Severity note: as of v0.1.12 the production path no longer uses this
	// replica to mutate outbound traffic — the probe is purely an
	// observation tool. A "mismatch" therefore does not imply anything is
	// wrong with the request being processed; it only records that the
	// historical replica algorithm has drifted from what this CLI version
	// produces. We keep INFO level for "mismatch" because operators do not
	// need to be paged for it; the entry is just data for offline reverse
	// engineering of the new algorithm.
	if state == "mismatch" || state == "no_suffix" {
		attrs = append(attrs, "client_block", blockText)
		logger.Info("disguise: billing algo probe — client suffix differs from historical replica (observation only)", attrs...)
	} else {
		logger.Info("disguise: billing algo probe — client suffix matches replica", attrs...)
	}
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
