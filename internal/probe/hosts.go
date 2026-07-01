package probe

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// hostsMarker delimits the block the probe adds to /etc/hosts so restore can
// remove exactly what it added and nothing else.
const (
	hostsBegin = "# >>> ccproxy probe (temporary) >>>"
	hostsEnd   = "# <<< ccproxy probe (temporary) <<<"
	hostsPath  = "/etc/hosts"
)

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
// byte, even if the probe is interrupted between add and restore in a way that
// leaves a partial block.
func addHostsEntries(hostnames []string) (*hostsGuard, error) {
	orig, err := os.ReadFile(hostsPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", hostsPath, err)
	}
	// Refuse if a stale probe block is already present — avoid nesting.
	if strings.Contains(string(orig), hostsBegin) {
		return nil, fmt.Errorf("a previous probe hosts block is still present in %s; "+
			"remove it manually before running", hostsPath)
	}

	var block strings.Builder
	block.WriteString("\n" + hostsBegin + "\n")
	for _, h := range hostnames {
		fmt.Fprintf(&block, "127.0.0.1\t%s\n", h)
		fmt.Fprintf(&block, "::1\t%s\n", h)
	}
	block.WriteString(hostsEnd + "\n")

	newContent := string(orig) + block.String()
	if err := writeRootFile(hostsPath, newContent); err != nil {
		return nil, err
	}
	return &hostsGuard{original: orig}, nil
}

// restore rewrites /etc/hosts back to its original snapshot.
func (g *hostsGuard) restore() {
	if g == nil || g.original == nil {
		return
	}
	if err := writeRootFile(hostsPath, string(g.original)); err != nil {
		fmt.Fprintf(os.Stderr, "probe: WARNING failed to restore %s: %v\n", hostsPath, err)
		fmt.Fprintf(os.Stderr, "probe: manually remove the block between %q and %q\n", hostsBegin, hostsEnd)
	}
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
