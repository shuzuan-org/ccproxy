package disguise

import (
	"encoding/json"
	"strings"
	"testing"
)

// mkFP builds a Fingerprint with the given StainlessOS. ClientID is set
// to a fixed value so all test assertions are stable across runs.
func mkFP(os string) *Fingerprint {
	return &Fingerprint{
		ClientID:                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		UserAgent:               "claude-cli/2.1.88 (external, cli)",
		StainlessPackageVersion: "0.74.0",
		StainlessOS:             os,
		StainlessArch:           "arm64",
		StainlessRuntimeVersion: "v22.13.0",
	}
}

// TestCanonicalEnvForFingerprint_PerOS pins the 3 OS buckets. Values must
// be deterministic for the same ClientID and must differ across OS.
func TestCanonicalEnvForFingerprint_PerOS(t *testing.T) {
	t.Parallel()

	mac := canonicalEnvForFingerprint(mkFP("MacOS"))
	if mac.Platform != "darwin" {
		t.Errorf("MacOS → Platform = %q, want darwin", mac.Platform)
	}
	if !strings.HasPrefix(mac.WorkingDir, "/Users/u") {
		t.Errorf("MacOS → WorkingDir = %q, want /Users/u…", mac.WorkingDir)
	}
	if mac.Shell != "/bin/zsh" {
		t.Errorf("MacOS → Shell = %q, want /bin/zsh", mac.Shell)
	}

	linux := canonicalEnvForFingerprint(mkFP("Linux"))
	if linux.Platform != "linux" {
		t.Errorf("Linux → Platform = %q, want linux", linux.Platform)
	}
	if !strings.HasPrefix(linux.WorkingDir, "/home/u") {
		t.Errorf("Linux → WorkingDir = %q, want /home/u…", linux.WorkingDir)
	}

	win := canonicalEnvForFingerprint(mkFP("Windows"))
	if win.Platform != "win32" {
		t.Errorf("Windows → Platform = %q, want win32", win.Platform)
	}
	if !strings.HasPrefix(win.WorkingDir, `C:\Users\u`) {
		t.Errorf("Windows → WorkingDir = %q, want C:\\Users\\u…", win.WorkingDir)
	}

	// All three must produce different WorkingDirs even when the
	// ClientID is identical — the suffix is mixed with the OS-specific
	// path prefix, but the slug itself is ClientID-only.
	if mac.WorkingDir == linux.WorkingDir || mac.WorkingDir == win.WorkingDir {
		t.Errorf("per-OS profiles must not collide:\n  mac=%q\n  linux=%q\n  win=%q",
			mac.WorkingDir, linux.WorkingDir, win.WorkingDir)
	}
}

// TestCanonicalEnvForFingerprint_StableForSameAccount is the invariant
// that enables prompt cache sharing: repeated calls for the same
// fingerprint must return byte-identical values.
func TestCanonicalEnvForFingerprint_StableForSameAccount(t *testing.T) {
	t.Parallel()
	fp := mkFP("MacOS")
	a := canonicalEnvForFingerprint(fp)
	b := canonicalEnvForFingerprint(fp)
	if a != b {
		t.Errorf("canonicalEnvForFingerprint not deterministic:\n  a=%+v\n  b=%+v", a, b)
	}
}

// TestCanonicalEnvForFingerprint_DifferentAccountsDiffer protects against
// an accidental "everyone has the same slug" regression. Two different
// ClientIDs must yield two different WorkingDirs.
func TestCanonicalEnvForFingerprint_DifferentAccountsDiffer(t *testing.T) {
	t.Parallel()
	a := canonicalEnvForFingerprint(&Fingerprint{
		ClientID:    "1111111111111111111111111111111111111111111111111111111111111111",
		StainlessOS: "MacOS",
	})
	b := canonicalEnvForFingerprint(&Fingerprint{
		ClientID:    "2222222222222222222222222222222222222222222222222222222222222222",
		StainlessOS: "MacOS",
	})
	if a.WorkingDir == b.WorkingDir {
		t.Errorf("different ClientIDs produced identical WorkingDir: %q", a.WorkingDir)
	}
}

// TestCanonicalEnvForFingerprint_NilFallback — nil fp must not panic.
func TestCanonicalEnvForFingerprint_NilFallback(t *testing.T) {
	t.Parallel()
	v := canonicalEnvForFingerprint(nil)
	if v.Platform == "" || v.WorkingDir == "" {
		t.Errorf("nil fp fallback left empty values: %+v", v)
	}
}

// TestRewriteEnvBlockInPlace_CanonicalSystemPrompt is the central happy
// path: a real Claude Code system prompt with an <env> block has its
// four fingerprint lines rewritten to per-account canonical values.
func TestRewriteEnvBlockInPlace_CanonicalSystemPrompt(t *testing.T) {
	t.Parallel()
	system := `You are Claude Code, Anthropic's official CLI for Claude.

Here is useful information about the environment you are running in:
<env>
Working directory: /Users/alice/code/myproj
Is directory a git repo: Yes
Platform: darwin
Shell: /bin/fish
OS Version: Darwin 23.6.0
</env>
You are powered by the model named Claude Opus 4.6.`
	parsed := parseJSON(t, `{"system":`+mustJSON(t, []map[string]interface{}{{
		"type": "text",
		"text": system,
	}})+`}`)

	rewriteEnvBlockInPlace(parsed, mkFP("Linux"))

	got := parsed["system"].([]interface{})[0].(map[string]interface{})["text"].(string)

	// All 4 fingerprint lines rewritten to Linux canonical values.
	if !strings.Contains(got, "Platform: linux") {
		t.Errorf("Platform not rewritten:\n%s", got)
	}
	if !strings.Contains(got, "Shell: /bin/bash") {
		t.Errorf("Shell not rewritten:\n%s", got)
	}
	if !strings.Contains(got, "OS Version: Linux 6.8.0-88-generic") {
		t.Errorf("OS Version not rewritten:\n%s", got)
	}
	if !strings.Contains(got, "Working directory: /home/u") {
		t.Errorf("Working directory not rewritten:\n%s", got)
	}

	// Original Darwin values must be gone.
	if strings.Contains(got, "/Users/alice") {
		t.Errorf("leaked original /Users/alice:\n%s", got)
	}
	if strings.Contains(got, "Darwin 23.6.0") {
		t.Errorf("leaked original Darwin 23.6.0:\n%s", got)
	}
	if strings.Contains(got, "/bin/fish") {
		t.Errorf("leaked original /bin/fish:\n%s", got)
	}

	// Non-env content must be preserved byte-for-byte.
	if !strings.Contains(got, "You are Claude Code, Anthropic's official CLI for Claude.") {
		t.Errorf("Claude Code prefix missing after rewrite:\n%s", got)
	}
	if !strings.Contains(got, "You are powered by the model named Claude Opus 4.6.") {
		t.Errorf("model description missing after rewrite:\n%s", got)
	}
	if !strings.Contains(got, "Is directory a git repo: Yes") {
		t.Errorf("non-fingerprint env line modified:\n%s", got)
	}
}

// TestRewriteEnvBlockInPlace_UserContentUntouched is the safety-critical
// test: even if a user happens to write text that looks like an <env>
// block in their message, we must not rewrite it, because the block
// lives outside a Claude Code system prompt.
func TestRewriteEnvBlockInPlace_UserContentUntouched(t *testing.T) {
	t.Parallel()
	// The key marker: the text does NOT start with a Claude Code prefix.
	// This simulates a user message or a third-party system prompt that
	// happens to contain <env>.
	userText := `Please help me debug this output:
<env>
Working directory: /Users/alice/code/myproj
Platform: darwin
</env>
What is wrong?`

	parsed := parseJSON(t, `{"system":`+mustJSON(t, []map[string]interface{}{{
		"type": "text",
		"text": userText,
	}})+`}`)

	rewriteEnvBlockInPlace(parsed, mkFP("Linux"))

	got := parsed["system"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if got != userText {
		t.Errorf("user-authored text was mutated:\n  want %q\n  got  %q", userText, got)
	}
}

// TestRewriteEnvBlockInPlace_StringSystem — parsed["system"] can be a
// bare string (legacy format). Must work the same way as the array form.
func TestRewriteEnvBlockInPlace_StringSystem(t *testing.T) {
	t.Parallel()
	system := "You are Claude Code, Anthropic's official CLI for Claude.\n" +
		"<env>\nWorking directory: /Users/alice/proj\nPlatform: darwin\n</env>"
	parsed := map[string]interface{}{"system": system}

	rewriteEnvBlockInPlace(parsed, mkFP("Linux"))

	got := parsed["system"].(string)
	if !strings.Contains(got, "Platform: linux") {
		t.Errorf("string-system Platform not rewritten:\n%s", got)
	}
	if strings.Contains(got, "/Users/alice") {
		t.Errorf("string-system leaked /Users/alice:\n%s", got)
	}
}

// TestRewriteEnvBlockInPlace_SystemReminderEnvelope verifies that env
// fingerprint lines inside <system-reminder> are also rewritten. Claude
// Code sometimes quotes env info back to the model via system-reminder.
func TestRewriteEnvBlockInPlace_SystemReminderEnvelope(t *testing.T) {
	t.Parallel()
	system := `You are Claude Code, Anthropic's official CLI for Claude.

Do your task.

<system-reminder>
Your current working directory is /Users/bob/work.
Platform: darwin
</system-reminder>`

	parsed := parseJSON(t, `{"system":`+mustJSON(t, []map[string]interface{}{{
		"type": "text",
		"text": system,
	}})+`}`)

	rewriteEnvBlockInPlace(parsed, mkFP("Linux"))

	got := parsed["system"].([]interface{})[0].(map[string]interface{})["text"].(string)
	if strings.Contains(got, "/Users/bob") {
		t.Errorf("system-reminder /Users/bob not swept:\n%s", got)
	}
	if !strings.Contains(got, "Platform: linux") {
		t.Errorf("system-reminder Platform not rewritten:\n%s", got)
	}
	// The "Do your task." sibling text must remain byte-identical.
	if !strings.Contains(got, "Do your task.") {
		t.Errorf("sibling text removed:\n%s", got)
	}
}

// TestRewriteEnvBlockInPlace_NoEnvBlock — blocks that match a Claude
// Code prefix but contain no <env> envelope should be a no-op.
func TestRewriteEnvBlockInPlace_NoEnvBlock(t *testing.T) {
	t.Parallel()
	system := "You are Claude Code, Anthropic's official CLI for Claude.\n\nHelp the user."
	parsed := map[string]interface{}{"system": system}

	rewriteEnvBlockInPlace(parsed, mkFP("MacOS"))

	got := parsed["system"].(string)
	if got != system {
		t.Errorf("no-env block was mutated:\n  want %q\n  got  %q", system, got)
	}
}

// TestRewriteEnvBlockInPlace_NilSafety — nil parsed, missing system,
// wrong type must all no-op without panicking.
func TestRewriteEnvBlockInPlace_NilSafety(t *testing.T) {
	t.Parallel()
	rewriteEnvBlockInPlace(nil, mkFP("Linux")) // must not panic

	parsed := map[string]interface{}{"messages": []interface{}{}}
	rewriteEnvBlockInPlace(parsed, mkFP("Linux"))

	parsed2 := map[string]interface{}{"system": 42}
	rewriteEnvBlockInPlace(parsed2, mkFP("Linux"))
}

// TestRewriteEnvBlockInPlace_PrimaryWorkingDirVariant — the
// non-interactive prompt uses "Primary working directory:" instead of
// "Working directory:". Both variants must be caught.
func TestRewriteEnvBlockInPlace_PrimaryWorkingDirVariant(t *testing.T) {
	t.Parallel()
	system := `You are a Claude agent, built on Anthropic's Claude Agent SDK.
<env>
Primary working directory: /Users/alice/scratch
Platform: darwin
</env>`

	parsed := map[string]interface{}{"system": system}
	rewriteEnvBlockInPlace(parsed, mkFP("Linux"))

	got := parsed["system"].(string)
	if strings.Contains(got, "/Users/alice") {
		t.Errorf("Primary working directory leaked original path:\n%s", got)
	}
	if !strings.Contains(got, "Primary working directory: /home/u") {
		t.Errorf("Primary working directory not rewritten:\n%s", got)
	}
}

// TestRewriteEnvBlockInPlace_MultipleClaudeCodeBlocks — the sub-agent
// prefix list has 8 entries. All of them should be recognized as "Claude
// Code system prompt" so their <env> blocks get rewritten.
func TestRewriteEnvBlockInPlace_MultipleClaudeCodeBlocks(t *testing.T) {
	t.Parallel()
	prefixes := []string{
		"You are Claude Code, Anthropic's official CLI for Claude",
		"You are a Claude agent, built on Anthropic's Claude Agent SDK",
		"You are an agent for Claude Code",
		"You are a file search specialist for Claude Code, Anthropic's official CLI for Claude.",
	}
	for _, prefix := range prefixes {
		prefix := prefix
		t.Run(prefix[:20], func(t *testing.T) {
			t.Parallel()
			text := prefix + "\n<env>\nPlatform: darwin\n</env>"
			parsed := map[string]interface{}{"system": text}
			rewriteEnvBlockInPlace(parsed, mkFP("Linux"))
			got := parsed["system"].(string)
			if !strings.Contains(got, "Platform: linux") {
				t.Errorf("prefix %q not recognized as Claude Code, env not rewritten:\n%s", prefix, got)
			}
		})
	}
}

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
