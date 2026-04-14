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

// BillingAlgoProbe passively validates our replica of Claude CLI's billing
// header fingerprint algorithm against real client traffic.
//
// Why this exists: our computeBillingFingerprint implementation is pinned to
// the algorithm observed in Claude CLI 2.1.88 (salt "59cf53e54c78", indices
// [4,7,20], sha256[:3]). If upstream changes the algorithm — different salt,
// different indices, different hash, different char offsets — any version
// upgrade we do via syncBillingHeaderVersion will produce wrong suffixes,
// which is a deterministic detection signal.
//
// We can't proactively test this because Anthropic doesn't publish the
// algorithm. Instead we PASSIVELY observe real CC clients: every time a
// client sends a billing header, we recompute what the suffix *would* be
// under our replica and compare to what the client actually sent. Match
// means the algorithm still applies to that client version; mismatch means
// we need to reverse engineer the new algorithm — and the log entry is the
// evidence we need to do so offline.
//
// Sampling: one entry per (UA_version, match_state) tuple. This gives two
// log lines per version at steady state (one "match" confirmation, one
// "mismatch" evidence if/when something breaks) and is reset at process
// restart so post-upgrade re-observation just works.
type BillingAlgoProbe struct {
	mu   sync.Mutex
	seen map[string]struct{} // key: "<ua_version>|<state>"
}

// NewBillingAlgoProbe returns a probe with fresh in-memory state.
func NewBillingAlgoProbe() *BillingAlgoProbe {
	return &BillingAlgoProbe{
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
func (p *BillingAlgoProbe) Observe(ctx context.Context, uaVersion, blockText, firstUserMessageText string) {
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
	expectedSuffix := computeBillingFingerprint(firstUserMessageText, clientVerTriple)

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
	if state == "mismatch" || state == "no_suffix" {
		attrs = append(attrs, "client_block", blockText)
		logger.Warn("disguise: billing algo probe — client suffix does not match our replica", attrs...)
	} else {
		logger.Info("disguise: billing algo probe — client suffix matches replica", attrs...)
	}
}

// hexChars encodes the bytes at the given indices of s into a hex string,
// using "00" for any index that's out of range. The output length is
// 2*len(indices). Matches the byte-level indexing used by
// computeBillingFingerprint — if the real algorithm is rune-based or UTF-16
// based (say, the client is JavaScript string-indexed), this function will
// record raw bytes for a human to compare.
func hexChars(s string, indices []int) string {
	buf := make([]byte, 0, 2*len(indices))
	for _, idx := range indices {
		var b byte
		if idx < len(s) {
			b = s[idx]
		}
		// 0x00 when out of range; note that computeBillingFingerprint uses
		// '0' (0x30) for out-of-range, not 0x00. We intentionally record
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
func (p *BillingAlgoProbe) ObserveParsedBody(ctx context.Context, parsed map[string]interface{}, uaVersion string) {
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
