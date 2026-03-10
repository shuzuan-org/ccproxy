package cli

import (
	"fmt"

	"github.com/binn/ccproxy/internal/config"
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}
		fmt.Printf("Starting ccproxy on %s:%d...\n", cfg.Server.Host, cfg.Server.Port)
		// TODO: implement server startup
		return nil
	},
}

func init() {
	rootCmd.AddCommand(startCmd)
}
