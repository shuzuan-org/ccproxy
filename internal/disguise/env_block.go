package disguise

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// The <env> system prompt block is injected by real Claude Code clients
// into every /v1/messages request. Its content comes from the local
// machine state at request time (getCwd, os.platform, uname -sr, shell
// name) — see claude-code:src/constants/prompts.ts:640. When a single
// OAuth account is shared by multiple users behind ccproxy, the raw
// <env> block gives Anthropic a deterministic per-request fingerprint of
// which human is at the keyboard (their cwd leaks their username, uname
// leaks their hardware, platform mixes darwin/linux across requests).
//
// rewriteEnvBlockInPlace replaces the four fingerprint lines inside any
// <env>...</env> or <system-reminder>...</system-reminder> block in the
// system prompt with per-account canonical values. It deliberately does
// NOT touch user message content — only text blocks in parsed["system"]
// whose content starts with the Claude Code sysprompt prefix are eligible.
//
// Mutates parsed in place. Callers marshal parsed once after all body
// transforms are complete. No-op when:
//   - parsed is nil or has no "system" field
//   - no system block contains an <env> or <system-reminder> envelope
//
// Call-order requirement: must run AFTER injectSystemPromptInPlace, because
// that function may prepend a Claude Code prefix block whose text is
// compared against existing blocks. This function does not care about the
// prefix block itself — it only rewrites content inside env envelopes.
//
// Why per-account (not global): a global canonical value would make every
// ccproxy request look like the exact same machine, which is itself a
// strong signal. Per-account derivation (stable across requests for the
// same account, different between accounts) mimics the real "one CLI
// install per laptop" distribution.

// envBlockValues is the per-account canonical values used to overwrite the
// <env> block's fingerprint lines.
type envBlockValues struct {
	Platform      string // "darwin" / "linux" / "win32"
	Shell         string // "/bin/zsh" / "/bin/bash" / etc.
	OSVersion     string // uname -sr equivalent, e.g. "Darwin 24.4.0"
	WorkingDir    string // "/Users/u6a8b2/projects/scratch"
	WorkingDirAlt string // home prefix used by the path normalizer below
}

// canonicalEnvForFingerprint derives a stable set of canonical env values
// from a Fingerprint's StainlessOS/StainlessArch + a per-account salt.
// The account salt is the ClientID (64-char hex, already stable), so two
// calls for the same account return the same struct.
//
// The derivation is deterministic so that repeated requests for the same
// account produce byte-identical <env> blocks — this keeps the system
// prompt prefix stable and gives Anthropic's prompt cache a chance to hit
// (see utils/api.ts:349 in claude-code: billing header block is cacheScope
// null but env block is inside the cacheable prefix).
func canonicalEnvForFingerprint(fp *Fingerprint) envBlockValues {
	if fp == nil {
		return envBlockValues{
			Platform:      "linux",
			Shell:         "/bin/bash",
			OSVersion:     "Linux 6.8.0-88-generic",
			WorkingDir:    "/home/dev/projects/scratch",
			WorkingDirAlt: "/home/dev/",
		}
	}

	// Stable 6-hex-char suffix derived from the fingerprint ClientID.
	// ClientID is already random per account (GenerateClientID), so hashing
	// it costs nothing but guarantees a single stable slug per account.
	suffix := clientIDSlug(fp.ClientID)

	switch fp.StainlessOS {
	case "MacOS":
		// Darwin kernel version matches Claude Code's canonical macOS test
		// bed. We do not rotate this per-account — a real CLI user's uname
		// -sr is stable across requests on the same machine. Per-account
		// drift comes from the WorkingDir slug, not the kernel version.
		return envBlockValues{
			Platform:      "darwin",
			Shell:         "/bin/zsh",
			OSVersion:     "Darwin 24.4.0",
			WorkingDir:    "/Users/u" + suffix + "/projects/scratch",
			WorkingDirAlt: "/Users/u" + suffix + "/",
		}
	case "Windows":
		// Real Claude CLI on Windows runs inside Git Bash or WSL in most
		// observed traffic; we pick the WSL shape to avoid backslash path
		// mismatches with the rest of the CLI's prompts.
		return envBlockValues{
			Platform:      "win32",
			Shell:         "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
			OSVersion:     "Windows_NT 10.0.22631",
			WorkingDir:    "C:\\Users\\u" + suffix + "\\projects\\scratch",
			WorkingDirAlt: "C:\\Users\\u" + suffix + "\\",
		}
	default:
		// "Linux" and any unknown OS fall through to the Linux profile.
		return envBlockValues{
			Platform:      "linux",
			Shell:         "/bin/bash",
			OSVersion:     "Linux 6.8.0-88-generic",
			WorkingDir:    "/home/u" + suffix + "/projects/scratch",
			WorkingDirAlt: "/home/u" + suffix + "/",
		}
	}
}

// clientIDSlug returns the first 6 hex chars of SHA256(clientID), or
// "default" if clientID is empty. The hash adds one level of indirection
// so two accounts that happened to be assigned adjacent ClientIDs do not
// also share adjacent slugs.
func clientIDSlug(clientID string) string {
	if clientID == "" {
		return "default"
	}
	sum := sha256.Sum256([]byte(clientID))
	return hex.EncodeToString(sum[:])[:6]
}

// envLineRe matches the four canonical <env> fingerprint lines. Each
// capture group 1 is the label + separator ("Platform: "), group 2 is the
// value we want to replace. The line terminator is not captured so the
// replacement preserves CRLF / LF as-is.
//
// The inter-label horizontal whitespace is matched with [ \t]* rather than
// \s*, because \s includes \n. If a hypothetical client emitted a label
// with an empty value ("Working directory:\n<next line>"), \s* would
// greedy-match across the newline and the following line would be captured
// as the "value" and overwritten. Real Claude CLI prompts always put a
// non-empty value on the same line as the label, so this is defensive
// hardening for future/malformed inputs rather than a fix for an observed
// production bug.
//
// The labels match both computeEnvInfo (Claude Code's interactive
// prompt) and computeSimpleEnvInfo (the non-interactive variant — note
// the "Primary working directory:" variant). See
// claude-code:src/constants/prompts.ts:640 and :677.
var (
	envPlatformRe       = regexp.MustCompile(`(Platform:[ \t]*)([^\r\n]+)`)
	envShellRe          = regexp.MustCompile(`(Shell:[ \t]*)([^\r\n]+)`)
	envOSVersionRe      = regexp.MustCompile(`(OS Version:[ \t]*)([^\r\n]+)`)
	envWorkingDirRe     = regexp.MustCompile(`((?:Primary )?Working directory:[ \t]*)([^\r\n]+)`)
	envHomePathRe       = regexp.MustCompile(`/(?:Users|home)/[^/\s"'\x60]+/`)
	envWorkingDirBlockRe = regexp.MustCompile(`(?s)<env>.*?</env>`)
	envSystemReminderRe  = regexp.MustCompile(`(?s)<system-reminder>.*?</system-reminder>`)
)

// rewriteEnvBlockInPlace walks parsed["system"] and rewrites every block
// whose text is a Claude Code system prompt. "Claude Code system prompt"
// is identified the same way detector.go:claudeCodePromptPrefixes does —
// the text must start with one of the known CLI prefixes. This guard is
// what keeps us away from user message content: user-authored content
// never starts with "You are Claude Code...".
//
// Inside a matched block, we rewrite only the lines that live within an
// <env>...</env> envelope or a <system-reminder>...</system-reminder>
// envelope (which may quote env info for the model). Lines outside both
// envelopes are left alone — they include tool documentation, guidelines,
// and other content that must not be touched.
func rewriteEnvBlockInPlace(parsed map[string]interface{}, fp *Fingerprint) {
	if parsed == nil {
		return
	}
	system, ok := parsed["system"]
	if !ok {
		return
	}
	values := canonicalEnvForFingerprint(fp)

	rewrite := func(text string) string {
		if !looksLikeClaudeCodeSystemPrompt(text) {
			return text
		}
		return rewriteEnvInText(text, values)
	}

	switch v := system.(type) {
	case string:
		parsed["system"] = rewrite(v)
	case []interface{}:
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			text, ok := m["text"].(string)
			if !ok {
				continue
			}
			m["text"] = rewrite(text)
		}
	}
}

// looksLikeClaudeCodeSystemPrompt returns true when text begins with any
// of the known Claude Code CLI sysprompt prefixes. This reuses the same
// prefix set the detector uses to classify clients, so the rewriter's
// definition of "system block" cannot drift from the detector's.
func looksLikeClaudeCodeSystemPrompt(text string) bool {
	trimmed := strings.TrimSpace(text)
	for _, prefix := range claudeCodePromptPrefixes {
		if strings.HasPrefix(trimmed, strings.TrimSpace(prefix)) {
			return true
		}
	}
	return false
}

// rewriteEnvInText performs the line-level substitution within a single
// Claude Code system prompt text block. It operates only inside <env>
// and <system-reminder> envelopes so that sibling content (tool docs,
// guidelines, etc.) is left byte-identical.
func rewriteEnvInText(text string, values envBlockValues) string {
	text = envWorkingDirBlockRe.ReplaceAllStringFunc(text, func(match string) string {
		return applyEnvLineSubs(match, values)
	})
	text = envSystemReminderRe.ReplaceAllStringFunc(text, func(match string) string {
		return applyEnvLineSubs(match, values)
	})
	return text
}

// applyEnvLineSubs applies the four line-level regex substitutions + the
// generic /Users|/home prefix sweep to a single envelope fragment.
func applyEnvLineSubs(fragment string, v envBlockValues) string {
	fragment = envPlatformRe.ReplaceAllString(fragment, "${1}"+v.Platform)
	fragment = envShellRe.ReplaceAllString(fragment, "${1}"+v.Shell)
	fragment = envOSVersionRe.ReplaceAllString(fragment, "${1}"+v.OSVersion)
	fragment = envWorkingDirRe.ReplaceAllString(fragment, "${1}"+v.WorkingDir)
	// Sweep any remaining home path references that weren't on their own
	// "Working directory:" line — e.g. "Additional working directories:
	// /Users/alice/other" or inline mentions in a system-reminder quote.
	// The sweep is intentionally coarse; if the envelope did not contain
	// any home path, it's a no-op.
	if v.WorkingDirAlt != "" {
		fragment = envHomePathRe.ReplaceAllString(fragment, v.WorkingDirAlt)
	}
	return fragment
}
