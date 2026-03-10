package cli

import (
	"database/sql"
	"fmt"

	"github.com/binn/ccproxy/internal/observability"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite" // SQLite driver
)

const dbFile = "data/ccproxy.db"

var statsHours int

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show token usage statistics",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Open the SQLite database
		db, err := sql.Open("sqlite", dbFile)
		if err != nil {
			return fmt.Errorf("open database %s: %w", dbFile, err)
		}
		defer func() { _ = db.Close() }()

		if err := db.Ping(); err != nil {
			return fmt.Errorf("connect to database: %w", err)
		}

		stats := observability.NewStats(db)
		rows, err := stats.TokenUsageByInstance(statsHours)
		if err != nil {
			return fmt.Errorf("query stats: %w", err)
		}

		if len(rows) == 0 {
			if statsHours > 0 {
				fmt.Printf("No requests recorded in the last %d hour(s).\n", statsHours)
			} else {
				fmt.Println("No requests recorded.")
			}
			return nil
		}

		// Print table header
		periodLabel := "all time"
		if statsHours > 0 {
			periodLabel = fmt.Sprintf("last %d hour(s)", statsHours)
		}
		fmt.Printf("Token usage statistics (%s)\n\n", periodLabel)

		// Header row
		fmt.Printf("%-24s %10s %10s %10s %12s %12s %14s %14s\n",
			"INSTANCE",
			"REQUESTS",
			"SUCCESS",
			"FAILURE",
			"INPUT TOKS",
			"OUTPUT TOKS",
			"CACHE CREATE",
			"CACHE READ",
		)

		// Separator
		fmt.Printf("%-24s %10s %10s %10s %12s %12s %14s %14s\n",
			"------------------------",
			"----------",
			"----------",
			"----------",
			"------------",
			"------------",
			"--------------",
			"--------------",
		)

		// Data rows
		for _, r := range rows {
			name := r.InstanceName
			if name == "" {
				name = "(unknown)"
			}
			fmt.Printf("%-24s %10d %10d %10d %12d %12d %14d %14d\n",
				name,
				r.TotalRequests,
				r.SuccessCount,
				r.FailureCount,
				r.InputTokens,
				r.OutputTokens,
				r.CacheCreationInputTokens,
				r.CacheReadInputTokens,
			)
		}

		return nil
	},
}

func init() {
	statsCmd.Flags().IntVar(&statsHours, "hours", 24, "Time window in hours (0 = all time)")
	rootCmd.AddCommand(statsCmd)
}
