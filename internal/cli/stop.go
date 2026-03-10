package cli

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

const pidFile = "data/ccproxy.pid"

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running ccproxy server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read PID from file
		// Note: the start command must write its PID to data/ccproxy.pid on startup
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

		// Send SIGTERM
		if err := proc.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
		}
		fmt.Printf("Sent SIGTERM to ccproxy (pid %d)...\n", pid)

		// Wait up to 5 seconds for the process to exit
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			// Signal 0 checks whether the process still exists without sending a real signal
			if err := proc.Signal(syscall.Signal(0)); err != nil {
				// Process is gone
				_ = os.Remove(pidFile)
				fmt.Println("ccproxy stopped.")
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}

		fmt.Printf("ccproxy (pid %d) did not exit within 5 seconds.\n", pid)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(stopCmd)
}
