package probe

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// hostsMarker delimits the block the probe adds to /etc/hosts so restore can
// remove exactly what it added and nothing else.
const (
	hostsBegin = "# >>> ccproxy probe (temporary) >>>"
	hostsEnd   = "# <<< ccproxy probe (temporary) <<<"
	hostsPath  = "/etc/hosts"
)

// validHostname permits only DNS-safe characters. Critically it forbids
// whitespace and newlines: without this check a hostname containing "\n" would
// let an attacker inject arbitrary lines into the root-owned /etc/hosts (e.g.
// remap api.anthropic.com), since the hostname is written verbatim into that
// file with root privileges. Every hostname is validated before any privileged
// write happens.
var validHostname = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

// hostsGuard tracks a temporary /etc/hosts modification so it can be reverted.
type hostsGuard struct {
	original []byte // full original file content, for exact restore
}

// addHostsEntries appends loopback mappings for the given hostnames to
// /etc/hosts, wrapped in a marker block. It shells out through `sudo` because
// /etc/hosts is root-owned; the user will be prompted for their password by
// sudo itself (the probe never handles it).
//
// It snapshots the original file first so restore() can put it back byte for
// byte. If a stale probe block from a previous interrupted run is present, it
// is stripped first (the block is marker-delimited, so removing it is safe and
// deterministic) rather than refusing to run — refusing would punish a user who
// Ctrl-C'd a prior run and leave them editing a system file by hand.
func addHostsEntries(hostnames []string) (*hostsGuard, error) {
	// Validate BEFORE touching anything privileged.
	for _, h := range hostnames {
		if !validHostname.MatchString(h) {
			return nil, fmt.Errorf("refusing to write invalid hostname %q to %s", h, hostsPath)
		}
	}

	orig, err := os.ReadFile(hostsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", hostsPath, err)
	}

	// The snapshot we restore to is the file WITHOUT any probe block — so
	// restore always yields a clean file even if a stale block was present.
	clean := stripProbeBlock(orig)

	var block strings.Builder
	block.WriteString("\n" + hostsBegin + "\n")
	for _, h := range hostnames {
		fmt.Fprintf(&block, "127.0.0.1\t%s\n", h)
		fmt.Fprintf(&block, "::1\t%s\n", h)
	}
	block.WriteString(hostsEnd + "\n")

	newContent := string(clean) + block.String()
	if err := writeRootFile(hostsPath, newContent); err != nil {
		return nil, err
	}
	return &hostsGuard{original: clean}, nil
}

// restore rewrites /etc/hosts back to the clean snapshot (original minus any
// probe block). Safe to call multiple times and on a nil guard.
func (g *hostsGuard) restore() {
	if g == nil || g.original == nil {
		return
	}
	if err := writeRootFile(hostsPath, string(g.original)); err != nil {
		fmt.Fprintf(os.Stderr, "probe: WARNING failed to restore %s: %v\n", hostsPath, err)
		fmt.Fprintf(os.Stderr, "probe: manually remove the block between %q and %q\n", hostsBegin, hostsEnd)
	}
}

// stripProbeBlock removes a marker-delimited probe block (and the single
// leading blank line addHostsEntries writes before it) from content. Content
// with no probe block is returned unchanged. Exposed logic kept pure for
// testing without touching the real /etc/hosts.
func stripProbeBlock(content []byte) []byte {
	s := string(content)
	start := strings.Index(s, hostsBegin)
	if start < 0 {
		return content
	}
	end := strings.Index(s, hostsEnd)
	if end < 0 || end < start {
		// Malformed (begin without end): cut from the marker to EOF so we never
		// leave a dangling half-block.
		trimmed := strings.TrimRight(s[:start], "\n")
		return []byte(trimmed + "\n")
	}
	end += len(hostsEnd)
	// Drop the block plus the leading newline we prepended, then re-normalize a
	// single trailing newline.
	before := strings.TrimRight(s[:start], "\n")
	after := s[end:]
	joined := before + after
	joined = strings.TrimRight(joined, "\n")
	if joined == "" {
		return []byte{}
	}
	return []byte(joined + "\n")
}

// writeRootFile writes content to a root-owned path via sudo tee. Using tee
// (rather than an in-process write) keeps the privileged operation a single,
// auditable command and works whether or not the probe itself runs as root.
func writeRootFile(path, content string) error {
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = strings.NewReader(content)
	cmd.Stdout = nil // discard tee's echo of the content
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sudo tee %s: %w", path, err)
	}
	return nil
}
