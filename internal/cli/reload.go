package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reload configuration without restarting",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read PID from file
		data, err := os.ReadFile(pidFile)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("pid file not found (%s): is ccproxy running?", pidFile)
			}
			return fmt.Errorf("read pid file: %w", err)
		}

		pidStr := strings.TrimSpace(string(data))
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return fmt.Errorf("invalid pid in %s: %q", pidFile, pidStr)
		}

		// Look up the process
		proc, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("find process %d: %w", pid, err)
		}

		// Send SIGHUP to trigger config reload
		if err := proc.Signal(syscall.SIGHUP); err != nil {
			return fmt.Errorf("send SIGHUP to %d: %w", pid, err)
		}

		fmt.Printf("Sent SIGHUP to ccproxy (pid %d) — configuration reload triggered.\n", pid)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(reloadCmd)
}
