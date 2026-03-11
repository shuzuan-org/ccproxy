package cli

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/server"
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	Version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "ccproxy",
	Short: "Claude API proxy with CLI impersonation",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		srv, err := server.New(cfg)
		if err != nil {
			return err
		}

		// Handle OS signals for graceful shutdown and config reload.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

		go func() {
			for sig := range sigCh {
				switch sig {
				case syscall.SIGINT, syscall.SIGTERM:
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					if err := srv.Shutdown(ctx); err != nil {
						log.Printf("shutdown error: %v", err)
					}
					cancel()
				case syscall.SIGHUP:
					log.Println("received SIGHUP, reloading config...")
					// Config reload will be implemented in Task 23.
				}
			}
		}()

		return srv.Start()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "config.toml", "config file path")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}

func Execute() error {
	return rootCmd.Execute()
}
