// Package disguise — 3-hex billing-header version suffix.
//
// The Claude CLI billing block looks like:
//
//	x-anthropic-billing-header: cc_version=2.1.126.125; cc_entrypoint=sdk-cli; cch=58e37;
//	                                          ^^^
//	                                          this 3-hex suffix
//
// It is computed as:
//
//	salt  = "59cf53e54c78"
//	chars = msg[4] + msg[7] + msg[20]   // each defaults to "0" if out of range
//	3hex  = sha256(salt + chars + version_triple).hex[:3]
//
// where `msg` is the text of the first user message that is NOT a system-injected
// "meta" message (Claude CLI internally sets isMeta=true on system reminders,
// tool result wrappers, mode-switch banners, etc.).
//
// In claude-code <= 2.1.104, the same algorithm operates on the wire body
// directly (no isMeta filter). In >= 2.1.105 the filter was added; the wire
// schema does not carry isMeta, so we must reconstruct it from prefix
// signatures observed in the binary's `_6({content: ..., isMeta:!0})`
// call sites.
//
// Reverse-engineered from the Bun-bundled JS source embedded in the Mach-O
// binary at /Users/binn/.local/share/claude/versions/2.1.126:
//
//	function vM3(H) {
//	    let _ = H.find((K) => K.type === "user" && !K.isMeta);
//	    if (!_) return "";
//	    let q = _.message.content;
//	    if (typeof q === "string") return q;
//	    if (Array.isArray(q)) {
//	        let K = q.find((O) => O.type === "text");
//	        if (K && K.type === "text") return K.text;
//	    }
//	    return "";
//	}
//	function GC8(H, _) {
//	    let K = [4,7,20].map((A) => H[A] || "0").join("");
//	    let O = `${kM3}${K}${_}`;
//	    return ajK.createHash("sha256").update(O).digest("hex").slice(0, 3);
//	}
//
// Validated against fresh_sample.bin (Claude Code 2.1.126, observed 3hex=125).
//
// Updating isMetaTextPrefixes for new client versions
//
// When verify_captured.py reports 3hex failures (cch.go is OK but
// three_hex diverges), the client introduced a new isMeta wrapper
// prefix. To find it:
//
//	# Look for new isMeta:!0 sites in the new binary, dump the
//	# surrounding ~300 bytes, extract `content:"..."` literals.
//	# Compare against isMetaTextPrefixes; add new ones.
//	python3 -c '
//	import re
//	with open("/path/to/new/claude-binary","rb") as f: data = f.read()
//	for m in re.finditer(rb"isMeta:!0", data):
//	    ctx = data[max(0,m.start()-300):m.start()].decode("latin1","replace")
//	    cm = re.search(r"content:[`\"]([^`\"]{1,200})", ctx)
//	    if cm: print(repr(cm.group(1)[:80]))
//	' | sort -u
//
// Then add any new prefix to isMetaTextPrefixes below and re-run
// verify_captured.py until 100% pass. See CLAUDE.md "Maintaining the
// cch / 3hex version whitelist" for the full procedure.
package disguise

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Note: salt + char-index constants are defined in billing_probe.go
// (billingFingerprintSalt, billingFingerprintCharIndices). We reuse them
// here so any future rotation only needs editing in one place.

// isMetaTextPrefixes lists wire-text prefixes that correspond to user
// messages flagged isMeta=true inside the Claude CLI before serialization.
// These are SYSTEM-INJECTED, not user-typed, and are skipped by the vM3
// "first user message" selector.
//
// Derived from 28 distinct content patterns at every isMeta:!0 call site
// in the 2.1.126 binary (see project_3hex_unreplicable.md memory). When
// claude-code adds new injection types or renames existing ones, rerun
// the binary scan and update this list — see scripts/extract_isMeta_patterns
// (TODO).
var isMetaTextPrefixes = []string{
	// System-reminder envelopes (most common): MCP instructions, available
	// skills, context injection, dynamic memory hints, env block, ...
	"<system-reminder>",

	// Slash-command wrappers — wire body has the local-command-caveat
	// envelope around them.
	"<local-command-caveat>",
	"<command-name>",
	"<local-command-stdout>",

	// Tool-result text wrappers (when claude-code converts a structured
	// tool_result into a user-text block for compaction).
	"Result of calling the ",
	"Called the ",

	// Mode-switch banners
	"## Exited Plan Mode",
	"## Exited Auto Mode",

	// Session continuity markers
	"Continue from where you left off.",
	"This session is being continued from another machine",
	"The date has changed.",

	// Hook + retry prompts
	"The PermissionDenied hook indicated",
	"Your tool call was malformed",
	"Output token limit hit. Resume directly",

	// Auto-mode reminders
	"Auto mode still active",
	"The user has asked you to work without stopping",

	// IDE / file-attachment wrappers
	"The user opened the file ",
	"The user selected the lines ",
	"The user has expressed a desire to invoke the agent",
	"Note: The file ",
	"Note: ",
	"Contents of ",
	"A plan file exists from plan mode at:",
	"The following skills are available for use",

	// MCP resources
	"<mcp-resource server=",

	// Snapshot / state
	"File snapshot",
}

// isMetaText returns true when the given user-message text block looks
// like a system-injected isMeta=true wrapper that vM3 would skip.
//
// Match is prefix-based after trimming leading whitespace, mirroring the
// Bun runtime which receives the JSON-decoded text verbatim and tests
// against literal prefixes (no normalization).
func isMetaText(text string) bool {
	t := strings.TrimLeft(text, " \t\r\n")
	for _, p := range isMetaTextPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// firstNonMetaUserText simulates vM3 over a wire-shaped messages array.
// Returns the text of the first content block (as string or first text
// item in an array) that does NOT match any isMetaText prefix. Returns ""
// when no such block exists — vM3 has the same fallthrough.
//
// `messages` is the parsed body's "messages" field; element type is
// expected to be []interface{} containing map[string]interface{} per the
// Anthropic Messages schema.
func firstNonMetaUserText(messages []interface{}) string {
	for _, m := range messages {
		msg, ok := m.(map[string]interface{})
		if !ok {
			continue
		}
		role, _ := msg["role"].(string)
		if role != "user" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if !isMetaText(content) {
				return content
			}
			// All blocks of this user message are meta — keep looking
			// at later user messages, mirroring vM3's H.find semantics
			// (which scans the entire array).
		case []interface{}:
			for _, b := range content {
				block, ok := b.(map[string]interface{})
				if !ok {
					continue
				}
				if t, _ := block["type"].(string); t != "text" {
					continue
				}
				text, _ := block["text"].(string)
				if isMetaText(text) {
					continue
				}
				return text
			}
		}
	}
	return ""
}

// Compute3HexSuffix returns the 3-hex billing-header version suffix for
// a request. `versionTriple` is the X.Y.Z portion of cc_version (no
// trailing .abc), `messages` is the parsed body's messages slice.
//
// Edge cases mirror the JS implementation:
//   - empty / out-of-range chars default to "0"
//   - no non-meta user message → all chars are "0", still produces a hash
func Compute3HexSuffix(versionTriple string, messages []interface{}) string {
	text := firstNonMetaUserText(messages)
	var chars [len(billingFingerprintCharIndices)]byte
	for i, idx := range billingFingerprintCharIndices {
		if idx < len(text) {
			chars[i] = text[idx]
		} else {
			chars[i] = '0'
		}
	}
	var sb strings.Builder
	sb.Grow(len(billingFingerprintSalt) + len(chars) + len(versionTriple))
	sb.WriteString(billingFingerprintSalt)
	sb.Write(chars[:])
	sb.WriteString(versionTriple)
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])[:3]
}
