package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
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
}

// NewHandler creates an admin Handler.
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config, registry *config.AccountRegistry) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
		registry: registry,
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
	if remaining < 5*time.Minute {
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
	actualCode := req.Code
	codeState := ""
	if idx := strings.Index(req.Code, "#"); idx != -1 {
		actualCode = req.Code[:idx]
		codeState = req.Code[idx+1:]
	}
	if subtle.ConstantTimeCompare([]byte(session.State), []byte(codeState)) != 1 {
		h.sessions.Delete(req.SessionID)
		writeError(w, http.StatusBadRequest, "invalid OAuth state parameter")
		return
	}

	// Exchange code for token (use actualCode without the appended state)
	slog.Info("oauth: completing login", "account", session.AccountName, "session_id", req.SessionID)
	proxyURL := h.registry.GetProxy(session.AccountName)
	token, err := h.oauthMgr.ExchangeAndSave(r.Context(), session.AccountName, actualCode, session.Verifier, proxyURL)
	if err != nil {
		slog.Error("oauth: login code exchange failed",
			"account", session.AccountName,
			"error", err.Error(),
		)
		h.sessions.Delete(req.SessionID)
		writeError(w, http.StatusBadGateway, "code exchange failed")
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
		writeError(w, http.StatusBadGateway, "refresh failed")
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
