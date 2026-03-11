package cli

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/spf13/cobra"
)

const dataDir = "data"

// oauthCmd is the parent command for all OAuth subcommands.
var oauthCmd = &cobra.Command{
	Use:   "oauth",
	Short: "Manage OAuth tokens",
}

// oauthLoginCmd starts a PKCE authorization flow for a given instance.
var oauthLoginCmd = &cobra.Command{
	Use:   "login <instance>",
	Short: "Authenticate an OAuth instance",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		instanceName := args[0]

		// Load config to validate instance
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// Find the requested instance
		if !findInstance(cfg, instanceName) {
			return fmt.Errorf("instance %q not found", instanceName)
		}

		// Build provider and token store
		provider := oauth.NewAnthropicProvider()
		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		// Generate PKCE verifier, challenge, and state
		verifier := oauth.GenerateVerifier()
		challenge := oauth.GenerateChallenge(verifier)
		state := oauth.GenerateState()

		// Build the authorization URL
		authURL := provider.AuthorizationURL(state, challenge)

		// Print the URL and try to copy to clipboard
		fmt.Println("Open the following URL in your browser to authorize:")
		fmt.Printf("\n  %s\n\n", authURL)
		copyToClipboard(authURL)

		// Read authorization code from stdin
		fmt.Println("After authorizing, paste the authorization code or the full callback URL below.")
		fmt.Print("Code: ")

		codeCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			if scanner.Scan() {
				codeCh <- strings.TrimSpace(scanner.Text())
			} else {
				errCh <- fmt.Errorf("failed to read input: %w", scanner.Err())
			}
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		var code string
		select {
		case raw := <-codeCh:
			if raw == "" {
				return fmt.Errorf("empty input — authorization aborted")
			}
			code = extractCode(raw, state)
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for authorization code (5 minutes)")
		}

		// Exchange the authorization code for tokens
		fmt.Println("Exchanging authorization code for tokens...")
		token, err := provider.ExchangeCode(context.Background(), code, verifier)
		if err != nil {
			return fmt.Errorf("exchange code: %w", err)
		}

		// Save tokens to the encrypted store keyed by instance name
		if err := store.Save(instanceName, *token); err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		fmt.Printf("Successfully logged in instance %q. Token expires at %s.\n",
			instanceName, token.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	},
}

// oauthStatusCmd shows the token status for all OAuth instances.
var oauthStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show OAuth token status for all instances",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		fmt.Printf("%-20s %-30s %s\n", "INSTANCE", "EXPIRES AT", "STATUS")
		fmt.Printf("%-20s %-30s %s\n", "--------------------", "------------------------------", "-------")

		found := false
		for _, inst := range cfg.Instances {
			found = true

			token, err := store.Load(inst.Name)
			if err != nil {
				fmt.Printf("%-20s %-30s %s\n", inst.Name, "—", fmt.Sprintf("error: %v", err))
				continue
			}
			if token == nil {
				fmt.Printf("%-20s %-30s %s\n", inst.Name, "—", "no token")
				continue
			}

			expiryStr := token.ExpiresAt.Local().Format(time.RFC3339)
			status := "valid"
			if time.Until(token.ExpiresAt) < 0 {
				status = "EXPIRED"
			} else if time.Until(token.ExpiresAt) < 5*time.Minute {
				status = "expiring soon"
			}

			fmt.Printf("%-20s %-30s %s\n", inst.Name, expiryStr, status)
		}

		if !found {
			fmt.Println("No OAuth instances configured.")
		}

		return nil
	},
}

// oauthRefreshCmd forces a token refresh for the given instance.
var oauthRefreshCmd = &cobra.Command{
	Use:   "refresh <instance>",
	Short: "Force refresh the OAuth token for an instance",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		instanceName := args[0]

		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		if !findInstance(cfg, instanceName) {
			return fmt.Errorf("instance %q not found", instanceName)
		}

		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		// Load existing token to get the refresh token
		existing, err := store.Load(instanceName)
		if err != nil {
			return fmt.Errorf("load token: %w", err)
		}
		if existing == nil {
			return fmt.Errorf("no stored token for %q — run 'ccproxy oauth login %s' first", instanceName, instanceName)
		}
		if existing.RefreshToken == "" {
			return fmt.Errorf("instance %q has no refresh token stored", instanceName)
		}

		provider := oauth.NewAnthropicProvider()

		fmt.Printf("Refreshing token for %q...\n", instanceName)
		newToken, err := provider.RefreshToken(context.Background(), existing.RefreshToken)
		if err != nil {
			return fmt.Errorf("refresh token: %w", err)
		}

		if err := store.Save(instanceName, *newToken); err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		fmt.Printf("Token refreshed. New expiry: %s\n", newToken.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	},
}

// oauthLogoutCmd deletes the stored token for the given instance.
var oauthLogoutCmd = &cobra.Command{
	Use:   "logout <instance>",
	Short: "Remove stored OAuth token for an instance",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		instanceName := args[0]

		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		if err := store.Delete(instanceName); err != nil {
			return fmt.Errorf("delete token: %w", err)
		}

		fmt.Printf("Logged out from %q.\n", instanceName)
		return nil
	},
}

func init() {
	oauthCmd.AddCommand(oauthLoginCmd)
	oauthCmd.AddCommand(oauthStatusCmd)
	oauthCmd.AddCommand(oauthRefreshCmd)
	oauthCmd.AddCommand(oauthLogoutCmd)
	rootCmd.AddCommand(oauthCmd)
}

// findInstance checks if the given name exists as an instance in config.
func findInstance(cfg *config.Config, name string) bool {
	for _, inst := range cfg.Instances {
		if inst.Name == name {
			return true
		}
	}
	return false
}

// copyToClipboard tries to copy text to the system clipboard.
// Failures are silently ignored — the user can always copy manually.
func copyToClipboard(text string) {
	// Try macOS pbcopy first, then Linux xclip
	for _, args := range [][]string{
		{"pbcopy"},
		{"xclip", "-selection", "clipboard"},
	} {
		c := exec.Command(args[0], args[1:]...)
		c.Stdin = strings.NewReader(text)
		if err := c.Run(); err == nil {
			fmt.Println("(URL copied to clipboard)")
			return
		}
	}
}

// extractCode parses user input that is either a bare authorization code
// or a full callback URL containing ?code=...&state=... parameters.
// When a full URL is provided, state is validated if present.
func extractCode(raw string, expectedState string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw // treat as bare code
	}
	q := u.Query()
	code := q.Get("code")
	if code == "" {
		return raw // not a recognizable callback URL
	}
	if st := q.Get("state"); st != "" && st != expectedState {
		fmt.Println("Warning: state parameter in URL does not match expected value.")
	}
	return code
}
