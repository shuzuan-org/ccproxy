package cli

import (
	"context"
	"log/slog"
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
		// Bootstrap logging with defaults; config.Load() will reconfigure
		// once the config file is parsed (so early logs like "config file
		// not found" still get the correct handler format).
		config.SetupLoggingDefaults()

		cfg, err := config.Load(cfgFile)
		if err != nil {
			return err
		}

		slog.Info("ccproxy starting", "version", Version, "config", cfgFile, "pid", os.Getpid())
		slog.Info("config loaded",
			"base_url", cfg.Server.BaseURL,
			"host", cfg.Server.Host,
			"port", cfg.Server.Port,
			"max_concurrency", cfg.Server.MaxConcurrency,
			"request_timeout", cfg.Server.RequestTimeout,
			"api_keys", len(cfg.APIKeys),
		)

		srv, err := server.New(cfg)
		if err != nil {
			return err
		}

		// Handle OS signals for graceful shutdown.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

		go func() {
			sig := <-sigCh
			slog.Info("received shutdown signal", "signal", sig.String())
			signal.Stop(sigCh)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := srv.Shutdown(ctx); err != nil {
				slog.Error("shutdown error", "error", err.Error())
			}
			cancel()
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
