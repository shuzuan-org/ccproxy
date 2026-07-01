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
// probe block) and reports whether it succeeded. On failure it emits a loud
// warning with manual-cleanup instructions; the caller is responsible for
// surfacing the failure (non-zero exit) rather than exiting as if clean —
// a root-owned file left modified is a security event, not a warning to bury.
// Safe to call multiple times and on a nil guard (nil counts as success:
// nothing to restore).
func (g *hostsGuard) restore() bool {
	if g == nil || g.original == nil {
		return true
	}
	if err := writeRootFile(hostsPath, string(g.original)); err != nil {
		fmt.Fprintf(os.Stderr, "probe: WARNING failed to restore %s: %v\n", hostsPath, err)
		fmt.Fprintf(os.Stderr, "probe: /etc/hosts STILL CONTAINS probe entries — remove the block "+
			"between %q and %q by hand.\n", hostsBegin, hostsEnd)
		return false
	}
	return true
}

// stripProbeBlock removes every marker-delimited probe block (and the single
// leading blank line addHostsEntries writes before each) from content. Content
// with no probe block is returned unchanged. It loops until no marker remains,
// so multiple blocks left by repeated/interrupted runs are all cleaned — a
// single strings.Index pass would leave the second block (and its
// domain→loopback lines) behind. Kept pure for testing without touching the
// real /etc/hosts.
func stripProbeBlock(content []byte) []byte {
	s := string(content)
	for {
		start := strings.Index(s, hostsBegin)
		if start < 0 {
			break
		}
		before := strings.TrimRight(s[:start], "\n")
		end := strings.Index(s, hostsEnd)
		if end < 0 || end < start {
			// Malformed (begin without a following end): cut from the marker to
			// EOF so we never leave a dangling half-block.
			s = before
			break
		}
		end += len(hostsEnd)
		after := s[end:]
		// Rejoin; a stripped middle block leaves before+after adjacent, which
		// the next iteration re-scans for further blocks.
		if before == "" {
			s = strings.TrimLeft(after, "\n")
		} else {
			s = before + "\n" + strings.TrimLeft(after, "\n")
		}
	}
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return []byte{}
	}
	return []byte(s + "\n")
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
