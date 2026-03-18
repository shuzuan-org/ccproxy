package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/updater"
	"github.com/spf13/cobra"
)

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Check for and apply updates",
	RunE: func(cmd *cobra.Command, args []string) error {
		config.SetupLoggingDefaults()

		checkOnly, _ := cmd.Flags().GetBool("check")
		force, _ := cmd.Flags().GetBool("force")

		// Load config to get update_repo.
		cfg, err := config.Load(cfgFile)
		if err != nil {
			slog.Warn("config load failed, using default repo", "error", err)
			cfg = &config.Config{}
			cfg.Server.UpdateRepo = "shuzuan-org/ccproxy"
		}

		repo := cfg.Server.UpdateRepo

		u := updater.New(updater.Config{
			CurrentVersion: Version,
			Repo:           repo,
			CheckInterval:  time.Hour, // unused for CLI
			AutoUpdate:     false,     // unused for CLI
		})

		if Version == "dev" {
			fmt.Fprintln(os.Stderr, "warning: running dev version, upgrade may not work as expected")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		fmt.Printf("Current version: %s\n", Version)
		fmt.Printf("Checking %s for updates...\n", repo)

		latest, err := u.CheckNow(ctx)
		if err != nil {
			return fmt.Errorf("check for updates: %w", err)
		}

		fmt.Printf("Latest version:  %s\n", latest)

		if checkOnly {
			if latest == Version {
				fmt.Println("Already up to date.")
			} else {
				fmt.Printf("Update available: %s → %s\n", Version, latest)
			}
			return nil
		}

		if latest == Version && !force {
			fmt.Println("Already up to date.")
			return nil
		}

		fmt.Printf("Upgrading %s → %s...\n", Version, latest)
		updated, newVer, err := u.Apply(ctx, force)
		if err != nil {
			return fmt.Errorf("apply update: %w", err)
		}
		if updated {
			fmt.Printf("Successfully upgraded to %s\n", newVer)
			fmt.Println("Restart ccproxy to use the new version.")
		} else {
			fmt.Println("No update applied.")
		}
		return nil
	},
}

func init() {
	upgradeCmd.Flags().Bool("check", false, "check only, do not apply")
	upgradeCmd.Flags().Bool("force", false, "force upgrade (allow downgrade)")
	rootCmd.AddCommand(upgradeCmd)
}
