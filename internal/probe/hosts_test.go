package probe

import (
	"strings"
	"testing"
)

func TestValidHostname_RejectsInjection(t *testing.T) {
	// The core security guard: a newline in a hostname would let arbitrary
	// lines be injected into the root-owned /etc/hosts.
	bad := []string{
		"evil.com\n127.0.0.1 api.anthropic.com",
		"has space.cn",
		"tab\there",
		"semi;colon",
		"",
		"-leadinghyphen.com",
		"trailinghyphen-",
	}
	for _, h := range bad {
		if validHostname.MatchString(h) {
			t.Errorf("hostname %q should be rejected but was accepted", h)
		}
	}
	good := []string{"probe-fp.cn", "yunwu.ai", "api.deepseek-probe.com", "probe-clean.example", "a.b.c.d"}
	for _, h := range good {
		if !validHostname.MatchString(h) {
			t.Errorf("hostname %q should be accepted but was rejected", h)
		}
	}
}

func TestAddHostsEntries_RejectsInvalidBeforeWrite(t *testing.T) {
	// Must fail on validation, never reaching the privileged write path.
	_, err := addHostsEntries([]string{"ok.cn", "bad\nhost"})
	if err == nil {
		t.Fatal("expected rejection of invalid hostname")
	}
	if !strings.Contains(err.Error(), "invalid hostname") {
		t.Errorf("error = %v, want invalid hostname rejection", err)
	}
}

func TestStripProbeBlock_NoBlock_Unchanged(t *testing.T) {
	orig := []byte("127.0.0.1\tlocalhost\n::1\tlocalhost\n")
	got := stripProbeBlock(orig)
	if string(got) != string(orig) {
		t.Fatalf("content without a block must be unchanged\n got=%q\nwant=%q", got, orig)
	}
}

func TestStripProbeBlock_RemovesBlockExactly(t *testing.T) {
	orig := "127.0.0.1\tlocalhost\n"
	withBlock := orig + "\n" + hostsBegin + "\n127.0.0.1\tprobe-fp.cn\n" + hostsEnd + "\n"
	got := stripProbeBlock([]byte(withBlock))
	if strings.Contains(string(got), hostsBegin) || strings.Contains(string(got), "probe-fp.cn") {
		t.Fatalf("probe block not fully removed: %q", got)
	}
	if !strings.Contains(string(got), "localhost") {
		t.Fatalf("original content must survive: %q", got)
	}
}

func TestStripProbeBlock_MalformedBeginOnly(t *testing.T) {
	// Begin marker with no end (interrupted write): cut to EOF, no dangling.
	withPartial := "127.0.0.1\tlocalhost\n\n" + hostsBegin + "\n127.0.0.1\tprobe-fp.cn\n"
	got := stripProbeBlock([]byte(withPartial))
	if strings.Contains(string(got), hostsBegin) || strings.Contains(string(got), "probe-fp.cn") {
		t.Fatalf("dangling half-block not removed: %q", got)
	}
	if !strings.Contains(string(got), "localhost") {
		t.Fatalf("original content must survive: %q", got)
	}
}

func TestStripProbeBlock_MultipleBlocks(t *testing.T) {
	// Two blocks (repeated/interrupted runs). A single strings.Index pass would
	// leave the second — and its domain→loopback lines — behind. All must go.
	block := func(h string) string {
		return "\n" + hostsBegin + "\n127.0.0.1\t" + h + "\n" + hostsEnd + "\n"
	}
	content := "127.0.0.1\tlocalhost\n" + block("probe-fp.cn") + block("yunwu.ai")
	got := string(stripProbeBlock([]byte(content)))
	if strings.Contains(got, hostsBegin) || strings.Contains(got, "probe-fp.cn") || strings.Contains(got, "yunwu.ai") {
		t.Fatalf("all probe blocks must be removed, got: %q", got)
	}
	if got != "127.0.0.1\tlocalhost\n" {
		t.Fatalf("original content must be preserved exactly, got: %q", got)
	}
}

func TestStripProbeBlock_Idempotent(t *testing.T) {
	orig := "127.0.0.1\tlocalhost\n"
	withBlock := orig + "\n" + hostsBegin + "\n127.0.0.1\tprobe-fp.cn\n" + hostsEnd + "\n"
	once := stripProbeBlock([]byte(withBlock))
	twice := stripProbeBlock(once)
	if string(once) != string(twice) {
		t.Fatalf("strip must be idempotent:\n once=%q\ntwice=%q", once, twice)
	}
}

func TestHostsGuard_NilRestoreSucceeds(t *testing.T) {
	var g *hostsGuard
	if !g.restore() {
		t.Fatal("nil guard restore must report success (nothing to restore)")
	}
}
