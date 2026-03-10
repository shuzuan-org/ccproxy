package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
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

// oauthLoginCmd starts a PKCE authorization flow for a given provider.
var oauthLoginCmd = &cobra.Command{
	Use:   "login <provider>",
	Short: "Authenticate with an OAuth provider via browser",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		providerName := args[0]

		// Load config to get provider settings
		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		// Find the requested provider
		var providerCfg *config.OAuthProviderConfig
		for i := range cfg.OAuthProviders {
			if cfg.OAuthProviders[i].Name == providerName {
				providerCfg = &cfg.OAuthProviders[i]
				break
			}
		}
		if providerCfg == nil {
			return fmt.Errorf("provider %q not found in config", providerName)
		}

		// Build provider and token store
		provider := oauth.NewAnthropicProvider(*providerCfg)
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

		// Open the URL in the browser (macOS: open, Linux: xdg-open)
		fmt.Printf("Opening browser for %s authorization...\n", providerName)
		fmt.Printf("If the browser does not open, visit:\n  %s\n\n", authURL)
		if err := exec.Command("open", authURL).Start(); err != nil {
			// Non-fatal: user can copy-paste the URL
			_ = exec.Command("xdg-open", authURL).Start()
		}

		// Start a temporary local HTTP server to receive the OAuth callback
		codeCh := make(chan string, 1)
		errCh := make(chan error, 1)

		// Extract the callback port from redirect_uri (default 8085)
		callbackAddr := ":8085"
		if providerCfg.RedirectURI != "" {
			// Try to parse port from redirect_uri like http://localhost:8085/callback
			if parsed, parseErr := parseCallbackAddr(providerCfg.RedirectURI); parseErr == nil {
				callbackAddr = parsed
			}
		}

		mux := http.NewServeMux()
		srv := &http.Server{
			Addr:    callbackAddr,
			Handler: mux,
		}

		mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()

			// Validate state to prevent CSRF
			if q.Get("state") != state {
				http.Error(w, "invalid state parameter", http.StatusBadRequest)
				errCh <- fmt.Errorf("state mismatch in callback")
				return
			}

			if errParam := q.Get("error"); errParam != "" {
				desc := q.Get("error_description")
				fmt.Fprintf(w, "<html><body><h2>Authorization failed: %s</h2><p>%s</p></body></html>", errParam, desc)
				errCh <- fmt.Errorf("authorization error: %s — %s", errParam, desc)
				return
			}

			code := q.Get("code")
			if code == "" {
				http.Error(w, "missing code parameter", http.StatusBadRequest)
				errCh <- fmt.Errorf("no authorization code in callback")
				return
			}

			fmt.Fprint(w, "<html><body><h2>Authorization successful!</h2><p>You may close this tab.</p></body></html>")
			codeCh <- code
		})

		// Start server in background
		go func() {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				errCh <- fmt.Errorf("callback server error: %w", err)
			}
		}()

		fmt.Printf("Waiting for authorization callback on %s...\n", callbackAddr)

		// Wait for code or error (timeout after 5 minutes)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		var code string
		select {
		case code = <-codeCh:
		case err = <-errCh:
			_ = srv.Shutdown(context.Background())
			return err
		case <-ctx.Done():
			_ = srv.Shutdown(context.Background())
			return fmt.Errorf("timed out waiting for authorization")
		}

		// Shutdown the callback server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutdownCancel()
		_ = srv.Shutdown(shutdownCtx)

		// Exchange the authorization code for tokens
		fmt.Println("Exchanging authorization code for tokens...")
		token, err := provider.ExchangeCode(context.Background(), code, verifier)
		if err != nil {
			return fmt.Errorf("exchange code: %w", err)
		}

		// Save tokens to the encrypted store
		if err := store.Save(providerName, *token); err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		fmt.Printf("Successfully logged in to %q. Token expires at %s.\n",
			providerName, token.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	},
}

// oauthStatusCmd shows the token status for all providers that have stored tokens.
var oauthStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show OAuth token status for all providers",
	RunE: func(cmd *cobra.Command, args []string) error {
		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		providers := store.List()
		if len(providers) == 0 {
			fmt.Println("No stored OAuth tokens found.")
			return nil
		}

		fmt.Printf("%-20s %-30s %s\n", "PROVIDER", "EXPIRES AT", "STATUS")
		fmt.Printf("%-20s %-30s %s\n", "--------------------", "------------------------------", "-------")

		for _, name := range providers {
			token, err := store.Load(name)
			if err != nil {
				fmt.Printf("%-20s %-30s %s\n", name, "—", fmt.Sprintf("error: %v", err))
				continue
			}
			if token == nil {
				fmt.Printf("%-20s %-30s %s\n", name, "—", "no token")
				continue
			}

			expiryStr := token.ExpiresAt.Local().Format(time.RFC3339)
			status := "valid"
			if time.Until(token.ExpiresAt) < 0 {
				status = "EXPIRED"
			} else if time.Until(token.ExpiresAt) < 5*time.Minute {
				status = "expiring soon"
			}

			fmt.Printf("%-20s %-30s %s\n", name, expiryStr, status)
		}

		return nil
	},
}

// oauthRefreshCmd forces a token refresh for the given provider.
var oauthRefreshCmd = &cobra.Command{
	Use:   "refresh <provider>",
	Short: "Force refresh the OAuth token for a provider",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		providerName := args[0]

		cfg, err := config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}

		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		// Load existing token to get the refresh token
		existing, err := store.Load(providerName)
		if err != nil {
			return fmt.Errorf("load token: %w", err)
		}
		if existing == nil {
			return fmt.Errorf("no stored token for %q — run 'ccproxy oauth login %s' first", providerName, providerName)
		}
		if existing.RefreshToken == "" {
			return fmt.Errorf("provider %q has no refresh token stored", providerName)
		}

		// Find provider config
		var providerCfg *config.OAuthProviderConfig
		for i := range cfg.OAuthProviders {
			if cfg.OAuthProviders[i].Name == providerName {
				providerCfg = &cfg.OAuthProviders[i]
				break
			}
		}
		if providerCfg == nil {
			return fmt.Errorf("provider %q not found in config", providerName)
		}

		provider := oauth.NewAnthropicProvider(*providerCfg)

		fmt.Printf("Refreshing token for %q...\n", providerName)
		newToken, err := provider.RefreshToken(context.Background(), existing.RefreshToken)
		if err != nil {
			return fmt.Errorf("refresh token: %w", err)
		}

		if err := store.Save(providerName, *newToken); err != nil {
			return fmt.Errorf("save token: %w", err)
		}

		fmt.Printf("Token refreshed. New expiry: %s\n", newToken.ExpiresAt.Local().Format(time.RFC3339))
		return nil
	},
}

// oauthLogoutCmd deletes the stored token for the given provider.
var oauthLogoutCmd = &cobra.Command{
	Use:   "logout <provider>",
	Short: "Remove stored OAuth token for a provider",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		providerName := args[0]

		store, err := oauth.NewTokenStore(dataDir)
		if err != nil {
			return fmt.Errorf("open token store: %w", err)
		}

		if err := store.Delete(providerName); err != nil {
			return fmt.Errorf("delete token: %w", err)
		}

		fmt.Printf("Logged out from %q.\n", providerName)
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

// parseCallbackAddr extracts ":port" from a redirect URI such as
// "http://localhost:8085/callback". Returns ":8085" in that example.
func parseCallbackAddr(redirectURI string) (string, error) {
	return parseAddrFromURI(redirectURI)
}

// parseAddrFromURI extracts the host:port from a URI and returns it in ":port" form.
func parseAddrFromURI(rawURI string) (string, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return "", fmt.Errorf("parse redirect URI: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		return "", fmt.Errorf("redirect URI %q has no port", rawURI)
	}
	if host == "" || host == "localhost" || host == "127.0.0.1" {
		return ":" + port, nil
	}
	return host + ":" + port, nil
}
