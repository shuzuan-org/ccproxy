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

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server",
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
					defer cancel()
					if err := srv.Shutdown(ctx); err != nil {
						log.Printf("shutdown error: %v", err)
					}
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
	rootCmd.AddCommand(startCmd)
}
