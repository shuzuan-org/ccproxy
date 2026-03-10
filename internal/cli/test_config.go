package cli

import (
	"fmt"

	"github.com/binn/ccproxy/internal/config"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Validate configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("config validation failed: %w", err)
		}
		fmt.Printf("Config OK: %d api keys, %d instances\n", len(cfg.APIKeys), len(cfg.Instances))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(testCmd)
}
