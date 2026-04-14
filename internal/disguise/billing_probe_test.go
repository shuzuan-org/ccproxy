package disguise

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// NOTE: The probe tests in this file all mutate slog.Default() via
// captureLogger, so they cannot run in parallel with each other (or with
// any other test that touches slog.Default). Do NOT add t.Parallel() calls.
// The shared-global tradeoff is deliberate — the alternative (injecting a
// logger into every probe call) would add noise to the production API for
// test-only benefit.

// captureLogger installs a slog handler that writes to a bytes.Buffer as
// the global default, and returns a restore function. Because this mutates
// process-global state, tests using it must be serial.
func captureLogger(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	buf := &bytes.Buffer{}
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	prev := slog.Default()
	slog.SetDefault(slog.New(h))
	return buf, func() { slog.SetDefault(prev) }
}

// makeBillingBlock builds the system array payload for a single billing block
// plus a user message, wired into a parsed body suitable for ObserveParsedBody.
func makeBillingBlock(blockText, userMsg string) map[string]interface{} {
	return map[string]interface{}{
		"system": []interface{}{
			map[string]interface{}{
				"type": "text",
				"text": blockText,
			},
		},
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": userMsg,
			},
		},
	}
}

func TestBillingProbe_MatchLogsOnceAsInfo(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	// Known vector: msg "hi" at 2.1.88 → suffix "758".
	parsed := makeBillingBlock(
		"x-anthropic-billing-header: cc_version=2.1.88.758; cc_entrypoint=cli;",
		"hi",
	)

	probe.ObserveParsedBody(context.Background(), parsed, "2.1.88")

	out := buf.String()
	if !strings.Contains(out, "state=match") {
		t.Errorf("expected state=match in log, got: %s", out)
	}
	if !strings.Contains(out, "ua_version=2.1.88") {
		t.Errorf("expected ua_version=2.1.88 in log, got: %s", out)
	}
	// Match logs do NOT include the raw block (lower noise, match is
	// confirmation not evidence).
	if strings.Contains(out, "client_block=") {
		t.Errorf("match log must not include raw block text, got: %s", out)
	}
	// Level is INFO for match.
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected INFO level for match, got: %s", out)
	}

	// Second call with the same (version, state) must NOT produce new log
	// output — dedup is the whole point.
	before := buf.Len()
	probe.ObserveParsedBody(context.Background(), parsed, "2.1.88")
	if buf.Len() != before {
		t.Errorf("dedup failed: second match call wrote new bytes, got:\n%s", buf.String()[before:])
	}
}

func TestBillingProbe_MismatchLogsOnceAsWarnWithRawBlock(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	// Client-sent suffix "xxx" deliberately wrong for msg=""/ver=2.1.88
	// (correct suffix is "758"). Simulates a future Claude CLI that changed
	// its fingerprint algorithm.
	parsed := makeBillingBlock(
		"x-anthropic-billing-header: cc_version=2.1.104.xxx; cc_entrypoint=cli; cch=sec12",
		"", // empty user message
	)

	probe.ObserveParsedBody(context.Background(), parsed, "2.1.104")

	out := buf.String()
	if !strings.Contains(out, "state=mismatch") {
		t.Errorf("expected state=mismatch in log, got: %s", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected INFO level for mismatch (probe is observation-only as of v0.1.12), got: %s", out)
	}
	// Mismatch logs MUST include the raw block — that's the evidence needed
	// to reverse-engineer the new algorithm offline.
	if !strings.Contains(out, "cc_entrypoint=cli") {
		t.Errorf("mismatch log must include raw block text, got: %s", out)
	}
	if !strings.Contains(out, "cch=sec12") {
		t.Errorf("mismatch log must preserve full block (cch field missing), got: %s", out)
	}
	// Must include chars_hex so a human can see what bytes went into the hash.
	if !strings.Contains(out, "chars_hex=") {
		t.Errorf("mismatch log must include chars_hex, got: %s", out)
	}
	// Must include the user message digest (not the raw text).
	if !strings.Contains(out, "msg_sha256_prefix=") {
		t.Errorf("mismatch log must include msg_sha256_prefix, got: %s", out)
	}

	// Dedup: second mismatch from same version is silent.
	before := buf.Len()
	probe.ObserveParsedBody(context.Background(), parsed, "2.1.104")
	if buf.Len() != before {
		t.Errorf("dedup failed: second mismatch call wrote new bytes")
	}
}

func TestBillingProbe_NoSuffixLogsAsWarnWithRawBlock(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	// Client sent cc_version without a suffix — unusual enough that we
	// treat it as a distinct state and want the full block for context.
	parsed := makeBillingBlock(
		"x-anthropic-billing-header: cc_version=2.1.104; cc_entrypoint=cli;",
		"hi",
	)

	probe.ObserveParsedBody(context.Background(), parsed, "2.1.104")

	out := buf.String()
	if !strings.Contains(out, "state=no_suffix") {
		t.Errorf("expected state=no_suffix, got: %s", out)
	}
	if !strings.Contains(out, "level=INFO") {
		t.Errorf("expected INFO level for no_suffix (probe is observation-only as of v0.1.12), got: %s", out)
	}
	if !strings.Contains(out, "cc_entrypoint=cli") {
		t.Errorf("no_suffix log must include raw block, got: %s", out)
	}
}

func TestBillingProbe_DifferentVersionsBothLogged(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	probe.ObserveParsedBody(
		context.Background(),
		makeBillingBlock("x-anthropic-billing-header: cc_version=2.1.88.758; cli", "hi"),
		"2.1.88",
	)
	probe.ObserveParsedBody(
		context.Background(),
		makeBillingBlock("x-anthropic-billing-header: cc_version=2.1.104.abc; cli", "hi"),
		"2.1.104",
	)

	out := buf.String()
	if !strings.Contains(out, "ua_version=2.1.88") {
		t.Errorf("missing 2.1.88 log entry: %s", out)
	}
	if !strings.Contains(out, "ua_version=2.1.104") {
		t.Errorf("missing 2.1.104 log entry: %s", out)
	}
}

func TestBillingProbe_DifferentStatesSameVersionBothLogged(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	// State 1: mismatch (wrong suffix for user_msg="" at 2.1.88)
	probe.ObserveParsedBody(
		context.Background(),
		makeBillingBlock("x-anthropic-billing-header: cc_version=2.1.88.zzz;", ""),
		"2.1.88",
	)
	// State 2: match for same version (suffix 758 is correct for msg=""/ver=2.1.88)
	probe.ObserveParsedBody(
		context.Background(),
		makeBillingBlock("x-anthropic-billing-header: cc_version=2.1.88.758;", ""),
		"2.1.88",
	)

	out := buf.String()
	// Both states should appear — (version, state) is the dedup key.
	if !strings.Contains(out, "state=mismatch") {
		t.Errorf("expected mismatch log: %s", out)
	}
	if !strings.Contains(out, "state=match") {
		t.Errorf("expected match log: %s", out)
	}
}

func TestBillingProbe_IgnoresEmptyUAVersion(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	parsed := makeBillingBlock("x-anthropic-billing-header: cc_version=2.1.88.758;", "hi")
	probe.ObserveParsedBody(context.Background(), parsed, "")

	if buf.Len() != 0 {
		t.Errorf("empty UA version must be a no-op, got: %s", buf.String())
	}
}

func TestBillingProbe_IgnoresNonBillingSystemBlocks(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	parsed := map[string]interface{}{
		"system": []interface{}{
			map[string]interface{}{
				"type": "text",
				"text": "You are Claude Code, Anthropic's official CLI for Claude.",
			},
			map[string]interface{}{
				"type": "text",
				"text": "Some user-supplied system prompt about cc_version=9.9.9.fake",
			},
		},
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "hi"},
		},
	}
	probe.ObserveParsedBody(context.Background(), parsed, "2.1.88")

	// Neither of those blocks starts with "x-anthropic-billing-header" so
	// the probe must ignore them entirely, even though the second one
	// contains a cc_version= substring.
	if buf.Len() != 0 {
		t.Errorf("non-billing blocks leaked into probe output: %s", buf.String())
	}
}

func TestBillingProbe_NilSafety(t *testing.T) {
	// serial: slog.Default is global — see package note
	var nilProbe *BillingHeaderObserver
	// Must not panic on nil receiver.
	nilProbe.ObserveParsedBody(context.Background(), nil, "2.1.88")
	nilProbe.Observe(context.Background(), "2.1.88", "", "")

	probe := NewBillingHeaderObserver()
	probe.ObserveParsedBody(context.Background(), nil, "2.1.88")
	probe.Observe(context.Background(), "2.1.88", "", "")
}

func TestBillingProbe_CharsHexForOutOfRangeIndices(t *testing.T) {
	// serial: slog.Default is global — see package note
	// 4 chars — indices 4,7,20 are all OOR → hex should be "000000"
	got := hexChars("abcd", []int{4, 7, 20})
	want := "000000"
	if got != want {
		t.Errorf("hexChars OOR: expected %q, got %q", want, got)
	}

	// Mix: index 4 in range, index 7 OOR, index 20 OOR.
	// "abcdeXYZ"[4] = 'e' = 0x65 → "65"
	got = hexChars("abcdeXYZ", []int{4, 7, 20})
	// idx 4 = 'e' (0x65), idx 7 = 'Z' (0x5a), idx 20 = OOR (0x00)
	want = "655a00"
	if got != want {
		t.Errorf("hexChars partial OOR: expected %q, got %q", want, got)
	}
}

func TestBillingProbe_ShortDigestStability(t *testing.T) {
	// serial: slog.Default is global — see package note
	// SHA256("") first 16 hex chars.
	got := shortDigest("")
	want := "e3b0c44298fc1c14"
	if got != want {
		t.Errorf("shortDigest(\"\"): expected %q, got %q", want, got)
	}
	// Non-empty — just verify length and determinism.
	a := shortDigest("hello")
	b := shortDigest("hello")
	if a != b {
		t.Errorf("shortDigest must be deterministic, got %q vs %q", a, b)
	}
	if len(a) != 16 {
		t.Errorf("shortDigest length: expected 16, got %d", len(a))
	}
}

func TestBillingProbe_StringSystemBilling(t *testing.T) {
	// serial: slog.Default is global — see package note
	buf, restore := captureLogger(t)
	defer restore()

	probe := NewBillingHeaderObserver()
	// system is a bare string (older API shape) rather than an array.
	parsed := map[string]interface{}{
		"system": "x-anthropic-billing-header: cc_version=2.1.88.758; cc_entrypoint=cli;",
		"messages": []interface{}{
			map[string]interface{}{"role": "user", "content": "hi"},
		},
	}
	probe.ObserveParsedBody(context.Background(), parsed, "2.1.88")

	if !strings.Contains(buf.String(), "state=match") {
		t.Errorf("expected match log for string system, got: %s", buf.String())
	}
}
