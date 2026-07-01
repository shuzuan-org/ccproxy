package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/probe"
	"github.com/spf13/cobra"
)

var (
	probeClaudeBin  string
	probePort       int
	probeOut        string
	probeVariants   string
	probeTimeout    time.Duration
	probeAllowHosts bool

	probeCompareUS string
	probeCompareCN string
)

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Detect covert client-side fingerprints via differential testing",
	Long: `Probe discovers hidden steganographic fingerprints a client embeds in its
outbound requests by differential testing: hold the semantic input fixed, flip
one environment dimension at a time, and observe whether the outbound bytes
drift. Any drift is a suspected fingerprint bit — no disassembly required.`,
}

var probeEnvCmd = &cobra.Command{
	Use:   "env",
	Short: "Run the local environment-matrix fingerprint scan",
	Long: `Starts a local sink that stands in for the Anthropic API, then drives the
real claude client once per environment variant (timezone, locale, proxy
hostname). It captures each outbound request body, normalizes away dynamic
fields, and diffs every variant against a clean baseline — reporting exactly
which environment dimension changes which bytes.

The timezone/locale variants always run. The host-dimension variants (which
test whether the client reacts to .cn / reseller / AI-lab proxy hostnames)
require resolving a hostname to loopback, which needs a temporary /etc/hosts
edit; enable it with --allow-hosts-edit (you will be prompted for sudo). When
not enabled, those variants are skipped and honestly marked as not driven.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		labels := map[string]bool{}
		for _, l := range strings.FieldsFunc(probeVariants, func(r rune) bool { return r == ',' || r == ' ' }) {
			labels[l] = true
		}
		report, err := probe.Run(probe.Config{
			ClaudeBin:      probeClaudeBin,
			Port:           probePort,
			OutDir:         probeOut,
			Variants:       labels,
			Timeout:        probeTimeout,
			AllowHostsEdit: probeAllowHosts,
			Logf: func(format string, a ...any) {
				fmt.Fprintf(cmd.ErrOrStderr(), "[probe] "+format+"\n", a...)
			},
		})
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), report)
		return nil
	},
}

func init() {
	probeEnvCmd.Flags().StringVar(&probeClaudeBin, "claude-bin", "", "path to claude executable (default: autodetect)")
	probeEnvCmd.Flags().IntVar(&probePort, "port", 0, "sink listen port (default: random free port)")
	probeEnvCmd.Flags().StringVar(&probeOut, "out", "", "directory to write captures and report (default: none)")
	probeEnvCmd.Flags().StringVar(&probeVariants, "variants", "", "comma-separated variant labels to run (default: all; baseline always included)")
	probeEnvCmd.Flags().DurationVar(&probeTimeout, "timeout", 90*time.Second, "per-variant client timeout")
	probeEnvCmd.Flags().BoolVar(&probeAllowHosts, "allow-hosts-edit", false, "allow temporary /etc/hosts edits (sudo) to drive host_* variants")

	probeCmd.AddCommand(probeEnvCmd)
	probeCmd.AddCommand(probeCompareCmd)
	rootCmd.AddCommand(probeCmd)
}

var probeCompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare two captured request bodies for geo-sensitive fingerprints",
	Long: `Diffs two request bodies captured on two real machines (e.g. a US VPS and a
CN VPS running the same client against the same prompt). Normalizes away dynamic
ids, then reports any character-level drift in the covert date line plus whether
the whole normalized bodies differ. Pure offline analysis — capture the bodies
elsewhere (ccproxy record mode, mitmproxy) and point --us / --cn at each.

Each of --us / --cn accepts a file, or a directory (the newest *.raw.json in it
is used).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if probeCompareUS == "" || probeCompareCN == "" {
			return fmt.Errorf("both --us and --cn are required")
		}
		bodyA, pathA, err := readBodyArg(probeCompareUS)
		if err != nil {
			return fmt.Errorf("--us: %w", err)
		}
		bodyB, pathB, err := readBodyArg(probeCompareCN)
		if err != nil {
			return fmt.Errorf("--cn: %w", err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "[probe] us=%s cn=%s\n", pathA, pathB)
		rep := probe.Compare("us", "cn", bodyA, bodyB)
		fmt.Fprintln(cmd.OutOrStdout(), rep.Render())
		return nil
	},
}

// readBodyArg reads a captured body from a file path, or from the newest
// *.raw.json inside a directory. Returns the bytes and the resolved path.
func readBodyArg(arg string) ([]byte, string, error) {
	fi, err := os.Stat(arg)
	if err != nil {
		return nil, "", err
	}
	path := arg
	if fi.IsDir() {
		matches, err := filepath.Glob(filepath.Join(arg, "*.raw.json"))
		if err != nil {
			return nil, "", err
		}
		if len(matches) == 0 {
			return nil, "", fmt.Errorf("no *.raw.json in directory %s", arg)
		}
		// Pick the most recently modified capture.
		newest, newestMod := matches[0], int64(0)
		for _, m := range matches {
			if s, err := os.Stat(m); err == nil && s.ModTime().UnixNano() > newestMod {
				newest, newestMod = m, s.ModTime().UnixNano()
			}
		}
		path = newest
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return data, path, nil
}

func init() {
	probeCompareCmd.Flags().StringVar(&probeCompareUS, "us", "", "captured body file or dir for the US side (required)")
	probeCompareCmd.Flags().StringVar(&probeCompareCN, "cn", "", "captured body file or dir for the CN side (required)")
}
