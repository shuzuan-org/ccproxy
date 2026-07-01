package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Outbound-body recording for fingerprint analysis.
//
// When CCPROXY_RECORD_DIR is set, every inbound client request body (the raw
// bytes the client emitted, before disguise/de-fingerprint) is written to that
// directory as a timestamp-free, monotonically-numbered *.raw.json file. This
// is the capture side of the two-location fingerprint comparison: run a client
// through the proxy on a US box and a CN box, then `ccproxy probe compare` the
// two recordings.
//
// It is deliberately env-gated, not a config field: it is a diagnostic used
// during an investigation, not a standing production feature, and must be
// trivially toggled per run without editing config.toml. Recording the RAW
// inbound body (not the disguised outbound one) is intentional — the client's
// fingerprint is what we compare across locations; the disguised outbound body
// has already had the fingerprint normalized out.

var recordSeq atomic.Uint64

// recordDir returns the configured recording directory, or "" if disabled.
func recordDir() string { return os.Getenv("CCPROXY_RECORD_DIR") }

// recordInboundBody writes body to the recording directory if recording is
// enabled. label is a short tag (e.g. api key name) folded into the filename
// for traceability. Failures are best-effort and never affect the request.
func recordInboundBody(body []byte, label string) {
	dir := recordDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	n := recordSeq.Add(1)
	// No timestamp in the name (Date.now()-free by design); the sequence number
	// plus label is enough to correlate, and keeps filenames deterministic.
	name := fmt.Sprintf("%06d-%s.raw.json", n, sanitizeLabel(label))
	_ = os.WriteFile(filepath.Join(dir, name), body, 0o644)
}

// sanitizeLabel keeps a label filename-safe.
func sanitizeLabel(s string) string {
	if s == "" {
		return "unknown"
	}
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
