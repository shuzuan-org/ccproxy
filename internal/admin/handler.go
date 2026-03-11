package admin

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
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
}

// NewHandler creates an admin Handler.
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
	}
}

// writeJSON writes v as JSON with Content-Type: application/json.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "json encode error", http.StatusInternalServerError)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// InstanceState holds the runtime state of a single backend instance.
type InstanceState struct {
	Name           string  `json:"name"`
	AuthMode       string  `json:"auth_mode"`
	LoadRate       int     `json:"load_rate"`
	ActiveSlots    int     `json:"active_slots"`
	MaxConcurrency int     `json:"max_concurrency"`
	Enabled        bool    `json:"enabled"`
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

// HandleInstances returns instance status with token info for OAuth instances.
// GET /api/instances
func (h *Handler) HandleInstances(w http.ResponseWriter, r *http.Request) {
	tracker := h.balancer.GetTracker()

	// Read all OAuth instances from config (includes disabled)
	states := make([]InstanceState, 0)
	for _, inst := range h.cfg.Instances {
		var loadRate, activeSlots int
		if inst.IsEnabled() {
			activeSlots, _, loadRate = tracker.LoadInfo(inst.Name, inst.MaxConcurrency)
		}

		state := InstanceState{
			Name:           inst.Name,
			AuthMode:       "oauth",
			LoadRate:       loadRate,
			ActiveSlots:    activeSlots,
			MaxConcurrency: inst.MaxConcurrency,
			Enabled:        inst.IsEnabled(),
		}

		// Add token info
		if h.oauthMgr != nil {
			token, _ := h.oauthMgr.Status(inst.Name)
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

// HandleOAuthLoginStart starts a PKCE OAuth flow for an instance.
// POST /api/oauth/login/start
func (h *Handler) HandleOAuthLoginStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !h.isOAuthInstance(req.Instance) {
		writeError(w, http.StatusBadRequest, "instance not found or not oauth")
		return
	}

	sessionID, authURL, err := h.sessions.Create(req.Instance)
	if err != nil {
		slog.Error("oauth: failed to create PKCE session", "instance", req.Instance, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	slog.Info("oauth: login started", "instance", req.Instance, "session_id", sessionID)
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	session, ok := h.sessions.Get(req.SessionID)
	if !ok {
		writeError(w, http.StatusBadRequest, "session not found or expired")
		return
	}

	// Exchange code for token
	slog.Info("oauth: completing login", "instance", session.InstanceName, "session_id", req.SessionID)
	provider := h.oauthMgr.GetProvider()
	token, err := provider.ExchangeCode(r.Context(), req.Code, session.Verifier)
	if err != nil {
		slog.Error("oauth: login code exchange failed",
			"instance", session.InstanceName,
			"error", err.Error(),
		)
		h.sessions.Delete(req.SessionID)
		writeError(w, http.StatusBadGateway, "code exchange failed: "+err.Error())
		return
	}

	// Save token keyed by instance name
	if err := h.oauthMgr.GetStore().Save(session.InstanceName, *token); err != nil {
		slog.Error("oauth: failed to save token", "instance", session.InstanceName, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to save token")
		return
	}

	h.sessions.Delete(req.SessionID)

	slog.Info("oauth: login complete",
		"instance", session.InstanceName,
		"expires_at", token.ExpiresAt.Format(time.RFC3339),
	)
	writeJSON(w, map[string]any{
		"ok":         true,
		"expires_at": token.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleOAuthRefresh forces a token refresh for an instance.
// POST /api/oauth/refresh
func (h *Handler) HandleOAuthRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !h.isOAuthInstance(req.Instance) {
		writeError(w, http.StatusBadRequest, "instance not found or not oauth")
		return
	}

	existing, err := h.oauthMgr.GetStore().Load(req.Instance)
	if err != nil || existing == nil {
		writeError(w, http.StatusBadRequest, "no token stored for this instance")
		return
	}
	if existing.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "no refresh token available")
		return
	}

	slog.Info("oauth: manual refresh requested", "instance", req.Instance)
	provider := h.oauthMgr.GetProvider()
	newToken, err := provider.RefreshToken(r.Context(), existing.RefreshToken)
	if err != nil {
		slog.Error("oauth: manual refresh failed", "instance", req.Instance, "error", err.Error())
		writeError(w, http.StatusBadGateway, "refresh failed: "+err.Error())
		return
	}

	if err := h.oauthMgr.GetStore().Save(req.Instance, *newToken); err != nil {
		slog.Error("oauth: failed to save refreshed token", "instance", req.Instance, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to save token")
		return
	}

	slog.Info("oauth: manual refresh success",
		"instance", req.Instance,
		"expires_at", newToken.ExpiresAt.Format(time.RFC3339),
	)
	writeJSON(w, map[string]any{
		"ok":         true,
		"expires_at": newToken.ExpiresAt.Format(time.RFC3339),
	})
}

// HandleOAuthLogout deletes the token for an instance.
// POST /api/oauth/logout
func (h *Handler) HandleOAuthLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Instance string `json:"instance"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.oauthMgr.GetStore().Delete(req.Instance); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete token")
		return
	}

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

// isOAuthInstance checks if the given name is a configured instance.
func (h *Handler) isOAuthInstance(name string) bool {
	for _, inst := range h.cfg.Instances {
		if inst.Name == name {
			return true
		}
	}
	return false
}
