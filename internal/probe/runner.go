package probe

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Config controls a probe env run.
type Config struct {
	// ClaudeBin is the path to the claude executable. Empty => autodetect.
	ClaudeBin string
	// Port is the sink port (0 => random free port).
	Port int
	// OutDir is where raw/normalized captures and the report are written.
	OutDir string
	// Variants limits the run to these labels (baseline always included).
	// Empty => full matrix.
	Variants map[string]bool
	// Timeout bounds each individual client invocation.
	Timeout time.Duration
	// Prompt is the fixed, deterministic prompt sent every run. Must contain no
	// time/randomness so the semantic input is constant across variants.
	Prompt string
	// AllowHostsEdit permits the runner to modify /etc/hosts (with sudo) to
	// resolve host-dimension variant hostnames to loopback. When false, host_*
	// variants are skipped-with-explanation.
	AllowHostsEdit bool
	// Logf receives progress lines (nil => discard).
	Logf func(string, ...any)
}

const defaultPrompt = "Reply with the single word: ok"

// Run executes the env-matrix probe end to end and returns the rendered report.
func Run(cfg Config) (string, error) {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Prompt == "" {
		cfg.Prompt = defaultPrompt
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 90 * time.Second
	}
	bin := cfg.ClaudeBin
	if bin == "" {
		var err error
		bin, err = detectClaude()
		if err != nil {
			return "", err
		}
	}
	cfg.Logf("using claude binary: %s", bin)

	if cfg.OutDir != "" {
		if err := os.MkdirAll(filepath.Join(cfg.OutDir, "runs"), 0o755); err != nil {
			return "", fmt.Errorf("mkdir out: %w", err)
		}
	}

	sink, err := StartSink(cfg.Port)
	if err != nil {
		return "", fmt.Errorf("start sink: %w", err)
	}
	defer sink.Close()
	cfg.Logf("sink listening on %s", sink.Addr())

	variants := Select(DefaultMatrix(), cfg.Variants)

	// Prepare hosts resolution for host_* variants if allowed.
	var hosts *hostsGuard
	if cfg.AllowHostsEdit {
		names := hostnamesNeeded(variants)
		if len(names) > 0 {
			hosts, err = addHostsEntries(names)
			if err != nil {
				cfg.Logf("warning: could not edit /etc/hosts (%v); host_* variants will be skipped", err)
				hosts = nil
			} else {
				defer hosts.restore()
				cfg.Logf("added temporary /etc/hosts entries for %d hostname(s)", len(names))
			}
		}
	}

	var results []VariantResult
	for _, v := range variants {
		res := driveVariant(cfg, sink, bin, v, hosts != nil)
		if cfg.OutDir != "" && res.Driven {
			writeCapture(cfg.OutDir, res)
		}
		results = append(results, res)
		status := "driven"
		if !res.Driven {
			status = "skipped: " + res.SkipReason
		}
		cfg.Logf("variant %-14s %s", v.Label, status)
	}

	report := BuildReport(results).Render()
	if cfg.OutDir != "" {
		_ = os.WriteFile(filepath.Join(cfg.OutDir, "report.txt"), []byte(report), 0o644)
	}
	return report, nil
}

// driveVariant runs the client under one variant and returns its result.
func driveVariant(cfg Config, sink *Sink, bin string, v Variant, hostsReady bool) VariantResult {
	res := VariantResult{Variant: v}

	// Determine the base URL the client should use.
	var baseURL string
	if v.NeedsHostResolve {
		if !hostsReady {
			res.SkipReason = "host dimension requires loopback name resolution " +
				"(/etc/hosts edit); not enabled (pass --allow-hosts-edit, needs sudo)"
			return res
		}
		baseURL = fmt.Sprintf("http://%s:%d", v.Hostname, sink.Port())
	} else {
		baseURL = "http://127.0.0.1:" + fmt.Sprint(sink.Port())
	}

	sink.Reset()

	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "-p", cfg.Prompt, "--output-format", "json")
	cmd.Env = buildEnv(v.Env, baseURL)
	// Isolate config/state so host machine settings don't leak in.
	cmd.Dir = os.TempDir()

	out, runErr := cmd.CombinedOutput()

	caps := sink.Captures()
	if len(caps) == 0 {
		reason := "client emitted no /v1/messages request"
		if runErr != nil {
			reason = fmt.Sprintf("%s; client error: %v; output: %s",
				reason, runErr, truncate(string(out), 300))
		}
		res.SkipReason = reason
		return res
	}

	// Use the first captured request (the primary turn).
	res.Driven = true
	res.RawBody = caps[0].Body
	// The covert date carrier can live in system[] or in a <system-reminder>
	// inside messages[] (2.1.197 uses the latter). DateLine finds it wherever
	// it is; that precise line is what we scan and diff, avoiding false
	// positives from legitimate markdown (backticks, em-dashes) elsewhere.
	res.DateLine = DateLine(caps[0].Body)
	res.SystemText = res.DateLine
	if res.DateLine != "" {
		res.Findings = ScanConfusables(res.DateLine)
	}
	return res
}

// buildEnv composes the child environment: inherit the current environment,
// apply the variant overlay, and pin ANTHROPIC_BASE_URL + a placeholder token.
func buildEnv(overlay map[string]string, baseURL string) []string {
	// Start from a filtered copy of the parent env, dropping keys we always set
	// so the overlay/pins win deterministically.
	drop := map[string]bool{
		"ANTHROPIC_BASE_URL":   true,
		"ANTHROPIC_AUTH_TOKEN": true,
		"ANTHROPIC_API_KEY":    true,
		"TZ":                   true,
		"LANG":                 true,
		"LC_ALL":               true,
	}
	var env []string
	for _, kv := range os.Environ() {
		k := kv[:strings.IndexByte(kv, '=')]
		if drop[k] {
			continue
		}
		env = append(env, kv)
	}
	for k, val := range overlay {
		env = append(env, k+"="+val)
	}
	env = append(env,
		"ANTHROPIC_BASE_URL="+baseURL,
		// Placeholder credential — the sink does not validate it.
		"ANTHROPIC_AUTH_TOKEN=sk-probe-placeholder",
	)
	return env
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// writeCapture persists the raw and normalized body for a driven variant.
func writeCapture(outDir string, res VariantResult) {
	base := filepath.Join(outDir, "runs", res.Variant.Label)
	_ = os.WriteFile(base+".raw.json", res.RawBody, 0o644)
	if norm, err := Normalize(res.RawBody); err == nil {
		_ = os.WriteFile(base+".norm.json", []byte(norm), 0o644)
	}
	if res.SystemText != "" {
		_ = os.WriteFile(base+".system.txt", []byte(res.SystemText), 0o644)
	}
}

// detectClaude locates the claude executable in the usual install locations.
func detectClaude() (string, error) {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".local/bin/claude"),
	}
	// Versioned installs: pick the highest version dir if present.
	if entries, err := os.ReadDir(filepath.Join(home, ".local/share/claude/versions")); err == nil {
		var best string
		for _, e := range entries {
			if e.Name() > best {
				best = e.Name()
			}
		}
		if best != "" {
			candidates = append(candidates, filepath.Join(home, ".local/share/claude/versions", best))
		}
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}
	if p, err := exec.LookPath("claude"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("could not locate claude binary; pass --claude-bin")
}

// hostnamesNeeded collects the distinct hostnames the host_* variants require.
func hostnamesNeeded(variants []Variant) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range variants {
		if v.NeedsHostResolve && v.Hostname != "" && !seen[v.Hostname] {
			seen[v.Hostname] = true
			out = append(out, v.Hostname)
		}
	}
	return out
}
