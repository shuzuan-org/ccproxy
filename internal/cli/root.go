package cli

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	Version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "ccproxy",
	Short: "Claude API proxy with CLI impersonation",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.toml", "config file path")
}

func Execute() error {
	return rootCmd.Execute()
}
