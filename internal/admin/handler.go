package admin

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/netutil"
	"github.com/binn/ccproxy/internal/oauth"
	"github.com/binn/ccproxy/internal/updater"
)

//go:embed static
var staticFiles embed.FS

// Handler provides HTTP handlers for the admin dashboard.
type Handler struct {
	balancer *loadbalancer.Balancer
	oauthMgr *oauth.Manager
	sessions *oauth.SessionStore
	cfg      *config.Config
	registry *config.AccountRegistry
	updater  *updater.Updater
}

// NewHandler creates an admin Handler.
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config, registry *config.AccountRegistry, upd *updater.Updater) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
		registry: registry,
		updater:  upd,
	}
}

// writeJSON writes v as JSON with Content-Type: application/json.
func writeJSON(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "json encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	data = append(data, '\n')
	_, _ = w.Write(data)
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// decodeBody decodes a JSON request body into v.
// Returns false and writes a 400 error if decoding fails.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

// AccountState holds the runtime state of a single backend account.
type AccountState struct {
	Name           string  `json:"name"`
	AuthMode       string  `json:"auth_mode"`
	LoadRate       int     `json:"load_rate"`
	ActiveSlots    int     `json:"active_slots"`
	MaxConcurrency int     `json:"max_concurrency"`
	Enabled        bool    `json:"enabled"`
	Proxy          string  `json:"proxy,omitempty"`
	TokenStatus    string  `json:"token_status,omitempty"`
	TokenExpiresAt *string `json:"token_expires_at,omitempty"`
	Health         string  `json:"health,omitempty"`
	Banned         bool    `json:"banned"`
	BanReason      string  `json:"ban_reason,omitempty"`
	DisabledReason string  `json:"disabled_reason,omitempty"`
	// Budget / utilization fields (from response headers + usage API)
	BudgetState string  `json:"budget_state,omitempty"` // "normal" | "sticky_only" | "blocked"
	Util5h      float64 `json:"util_5h"`                // 0–1
	Util7d      float64 `json:"util_7d"`                // 0–1
	ResetAt5h   *string `json:"reset_at_5h,omitempty"`  // RFC3339
	ResetAt7d   *string `json:"reset_at_7d,omitempty"`  // RFC3339
}

// tokenStatus returns a human-readable status for an OAuth token.
func tokenStatus(token *oauth.OAuthToken) string {
	if token == nil {
		return "no token"
	}
	remaining := time.Until(token.ExpiresAt)
	if remaining < 0 {
		return "expired"
	}
	if remaining < 30*time.Minute {
		return "expiring soon"
	}
	return "valid"
}

// HandleAccounts returns account status with token info for OAuth accounts.
// GET /api/accounts
func (h *Handler) HandleAccounts(w http.ResponseWriter, r *http.Request) {
	tracker := h.balancer.GetTracker()
	maxConcurrency := h.cfg.Server.MaxConcurrency

	entries := h.registry.List()
	states := make([]AccountState, 0, len(entries))
	for _, entry := range entries {
		var loadRate, activeSlots int
		if entry.Enabled {
			activeSlots, _, loadRate = tracker.LoadInfo(entry.Name, maxConcurrency)
		}

		state := AccountState{
			Name:           entry.Name,
			AuthMode:       "oauth",
			LoadRate:       loadRate,
			ActiveSlots:    activeSlots,
			MaxConcurrency: maxConcurrency,
			Enabled:        entry.Enabled,
			Proxy:          entry.Proxy,
		}

		if health := h.balancer.GetHealth(entry.Name); health != nil {
			state.Health = "healthy"
			if health.IsBanned() {
				state.Health = "banned"
			} else if health.IsDisabled() {
				state.Health = "disabled"
			} else if !health.IsAvailable() {
				state.Health = "cooldown"
			}
			state.Banned = health.IsBanned()
			state.BanReason = health.BanReason()
			state.DisabledReason = health.DisabledReason()

			if budget := health.Budget(); budget != nil {
				w5h := budget.Window5h()
				w7d := budget.Window7d()
				state.BudgetState = budget.State().String()
				state.Util5h = w5h.Utilization
				state.Util7d = w7d.Utilization
				if !w5h.ResetAt.IsZero() {
					r := w5h.ResetAt.Format(time.RFC3339)
					state.ResetAt5h = &r
				}
				if !w7d.ResetAt.IsZero() {
					r := w7d.ResetAt.Format(time.RFC3339)
					state.ResetAt7d = &r
				}
			}
		}

		// Add token info
		if h.oauthMgr != nil {
			token, _ := h.oauthMgr.Status(entry.Name)
			state.TokenStatus = tokenStatus(token)
			if token != nil {
				exp := token.ExpiresAt.Format(time.RFC3339)
				state.TokenExpiresAt = &exp
			}
		}

		states = append(states, state)
	}
	writeJSON(w, states)
}

// HandleOAuthLoginStart starts a PKCE OAuth flow for an account.
// POST /api/oauth/login/start
func (h *Handler) HandleOAuthLoginStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if !h.isOAuthAccount(req.Account) {
		writeError(w, http.StatusBadRequest, "account not found or not oauth")
		return
	}

	sessionID, authURL, err := h.sessions.Create(req.Account)
	if err != nil {
		slog.Error("oauth: failed to create PKCE session", "account", req.Account, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	slog.Info("oauth: login started", "account", req.Account, "session_id", sessionID)
	writeJSON(w, map[string]string{
		"session_id":        sessionID,
		"authorization_url": authURL,
	})
}

// HandleOAuthLoginComplete completes a PKCE OAuth flow.
// POST /api/oauth/login/complete
func (h *Handler) HandleOAuthLoginComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SessionID string `json:"session_id"`
		Code      string `json:"code"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	session, ok := h.sessions.Get(req.SessionID)
	if !ok {
		writeError(w, http.StatusBadRequest, "session not found or expired")
		return
	}

	// Validate OAuth state parameter to prevent CSRF.
	// The code field may contain "authcode#state" (state appended by frontend).
	codeState := ""
	if idx := strings.Index(req.Code, "#"); idx != -1 {
		codeState = req.Code[idx+1:]
	}
	if subtle.ConstantTimeCompare([]byte(session.State), []byte(codeState)) != 1 {
		h.sessions.Delete(req.SessionID)
		writeError(w, http.StatusBadRequest, "invalid OAuth state parameter")
		return
	}

	// Exchange code for token (pass full code with #state so provider sends state to Anthropic)
	slog.Info("oauth: completing login", "account", session.AccountName, "session_id", req.SessionID)
	proxyURL := h.registry.GetProxy(session.AccountName)
	token, err := h.oauthMgr.ExchangeAndSave(r.Context(), session.AccountName, req.Code, session.Verifier, proxyURL)
	if err != nil {
		slog.Error("oauth: login code exchange failed",
			"account", session.AccountName,
			"error", err.Error(),
		)
		writeError(w, http.StatusBadRequest, "code exchange failed: "+err.Error())
		return
	}

	h.sessions.Delete(req.SessionID)

	slog.Info("oauth: login complete",
		"account", session.AccountName,
		"expires_at", token.ExpiresAt.Format(time.RFC3339),
	)
	writeJSON(w, map[string]any{
		"ok":         true,
		"expires_at": token.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleOAuthRefresh forces a token refresh for an account.
// POST /api/oauth/refresh
func (h *Handler) HandleOAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if !h.isOAuthAccount(req.Account) {
		writeError(w, http.StatusBadRequest, "account not found or not oauth")
		return
	}

	slog.Info("oauth: manual refresh requested", "account", req.Account)
	newToken, err := h.oauthMgr.ForceRefresh(r.Context(), req.Account)
	if err != nil {
		slog.Error("oauth: manual refresh failed", "account", req.Account, "error", err.Error())
		writeError(w, http.StatusBadRequest, "refresh failed: "+err.Error())
		return
	}

	slog.Info("oauth: manual refresh success",
		"account", req.Account,
		"expires_at", newToken.ExpiresAt.Format(time.RFC3339),
	)
	writeJSON(w, map[string]any{
		"ok":         true,
		"expires_at": newToken.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleOAuthLogout deletes the token for an account.
// POST /api/oauth/logout
func (h *Handler) HandleOAuthLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if err := h.oauthMgr.Logout(req.Account); err != nil {
		slog.Error("oauth: logout failed to delete token", "account", req.Account, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete token")
		return
	}

	slog.Info("oauth: logout success", "account", req.Account)
	writeJSON(w, map[string]bool{"ok": true})
}

// HandleSessions returns active session list (placeholder).
// GET /api/sessions
func (h *Handler) HandleSessions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, []struct{}{})
}

// HandleDashboard serves the embedded static HTML dashboard.
// GET /admin/*
func (h *Handler) HandleDashboard() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("admin: failed to sub static fs: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}

// isOAuthAccount checks if the given name is a configured account.
func (h *Handler) isOAuthAccount(name string) bool {
	return h.registry.Has(name)
}

// HandleAddAccount adds a new account to the registry.
// POST /api/accounts/add
func (h *Handler) HandleAddAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if err := h.registry.Add(req.Name); err != nil {
		slog.Warn("add account failed", "name", req.Name, "error", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ensure the oauth manager knows about the new account.
	h.oauthMgr.UpdateAccounts(h.registry.Names())

	slog.Info("account added", "name", req.Name)
	writeJSON(w, map[string]bool{"ok": true})
}

// HandleRemoveAccount removes an account from the registry and cleans up its OAuth token.
// POST /api/accounts/remove
func (h *Handler) HandleRemoveAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	// Clean up OAuth token before removing.
	if err := h.oauthMgr.Logout(req.Name); err != nil {
		slog.Warn("failed to delete oauth token on account removal", "name", req.Name, "error", err.Error())
	}

	if err := h.registry.Remove(req.Name); err != nil {
		slog.Warn("remove account failed", "name", req.Name, "error", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update oauth manager account list.
	h.oauthMgr.UpdateAccounts(h.registry.Names())

	slog.Info("account removed", "name", req.Name)
	writeJSON(w, map[string]bool{"ok": true})
}

// HandleUpdateProxy updates the proxy URL for an account.
// POST /api/accounts/proxy
func (h *Handler) HandleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Proxy string `json:"proxy"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if err := h.registry.UpdateProxy(req.Name, req.Proxy); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("account proxy updated", "name", req.Name, "proxy", req.Proxy)
	writeJSON(w, map[string]bool{"ok": true})
}

// testModel is the model used for account connectivity tests. Use a small,
// fast model to minimise cost and latency.
const testModel = "claude-haiku-4-5-20251001"
// OAuth token to verify the token and network path are working.
// POST /api/accounts/test
func (h *Handler) HandleTestAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if !h.registry.Has(req.Account) {
		writeError(w, http.StatusBadRequest, "account not found")
		return
	}

	token, err := h.oauthMgr.GetValidToken(r.Context(), req.Account)
	if err != nil || token == nil {
		writeError(w, http.StatusBadRequest, "no valid token for this account — please login first")
		return
	}

	// Build HTTP client, respecting account-level SOCKS5 proxy.
	httpClient := &http.Client{Timeout: 15 * time.Second}
	if proxyURL := h.registry.GetProxy(req.Account); proxyURL != "" {
		if dialer, dialErr := netutil.NewSOCKS5Dialer(proxyURL); dialErr == nil {
			httpClient.Transport = &http.Transport{
				TLSHandshakeTimeout: 10 * time.Second,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				},
			}
		}
	}

	body, _ := json.Marshal(map[string]any{
		"model":      testModel,
		"max_tokens": 50,
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
	})

	apiReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build request")
		return
	}
	apiReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
	apiReq.Header.Set("anthropic-version", "2023-06-01")
	apiReq.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(apiReq)
	if err != nil {
		writeError(w, http.StatusBadGateway, "request failed: "+err.Error())
		return
	}
	defer resp.Body.Close()

	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		writeError(w, http.StatusBadGateway, "failed to decode response")
		return
	}

	if resp.StatusCode != http.StatusOK {
		msg := result.Error.Message
		if msg == "" {
			msg = "HTTP " + strconv.Itoa(resp.StatusCode)
		}
		slog.Warn("account test failed", "account", req.Account, "status", resp.StatusCode, "error", msg)
		writeError(w, http.StatusBadGateway, msg)
		return
	}

	reply := ""
	if len(result.Content) > 0 {
		reply = result.Content[0].Text
	}
	slog.Info("account test passed", "account", req.Account)
	writeJSON(w, map[string]any{"ok": true, "reply": reply})
}
