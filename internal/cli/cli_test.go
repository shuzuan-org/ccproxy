package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestVersionCmd_Output(t *testing.T) {
	// versionCmd uses fmt.Printf which writes to os.Stdout.
	// Capture by redirecting stdout.
	original := Version
	Version = "1.2.3-test"
	defer func() { Version = original }()

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	versionCmd.Run(versionCmd, nil)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	if !strings.Contains(output, "1.2.3-test") {
		t.Errorf("output = %q, want it to contain version", output)
	}
}

func TestRootCmd_ConfigFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("expected --config flag")
	}
	if flag.DefValue != "config.toml" {
		t.Errorf("default = %q, want config.toml", flag.DefValue)
	}
	if flag.Shorthand != "c" {
		t.Errorf("shorthand = %q, want c", flag.Shorthand)
	}
}
