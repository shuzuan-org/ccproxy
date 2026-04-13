package admin

import (
	"bytes"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/disguise"
	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/oauth"
	proxytls "github.com/binn/ccproxy/internal/tls"
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
	dataDir  string
}

// NewHandler creates an admin Handler.
func NewHandler(balancer *loadbalancer.Balancer, oauthMgr *oauth.Manager, sessions *oauth.SessionStore, cfg *config.Config, registry *config.AccountRegistry, upd *updater.Updater, dataDir string) *Handler {
	return &Handler{
		balancer: balancer,
		oauthMgr: oauthMgr,
		sessions: sessions,
		cfg:      cfg,
		registry: registry,
		updater:  upd,
		dataDir:  dataDir,
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

// HandleAuthMe returns the authenticated user's identity.
// GET /api/auth/me
func (h *Handler) HandleAuthMe(w http.ResponseWriter, r *http.Request) {
	auth := GetAdminAuth(r.Context())
	if auth == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	writeJSON(w, map[string]any{
		"username": auth.Username,
		"is_admin": auth.IsAdmin,
	})
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
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Owner          string  `json:"owner,omitempty"`
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
// Admin sees all accounts (read-only), users see only their own.
// GET /api/accounts
func (h *Handler) HandleAccounts(w http.ResponseWriter, r *http.Request) {
	auth := GetAdminAuth(r.Context())
	tracker := h.balancer.GetTracker()
	maxConcurrency := h.cfg.Server.MaxConcurrency

	var entries []config.Account
	if auth != nil && auth.IsAdmin {
		entries = h.registry.List()
	} else if auth != nil {
		entries = h.registry.ListByOwner(auth.Username)
	}

	states := make([]AccountState, 0, len(entries))
	for _, entry := range entries {
		var loadRate, activeSlots int
		if entry.Enabled {
			activeSlots, _, loadRate = tracker.LoadInfo(entry.ID, maxConcurrency)
		}

		state := AccountState{
			ID:             entry.ID,
			Name:           entry.Name,
			Owner:          entry.Owner,
			AuthMode:       "oauth",
			LoadRate:       loadRate,
			ActiveSlots:    activeSlots,
			MaxConcurrency: maxConcurrency,
			Enabled:        entry.Enabled,
			Proxy:          entry.Proxy,
		}

		if health := h.balancer.GetHealth(entry.ID); health != nil {
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
			token, _ := h.oauthMgr.Status(entry.ID)
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

// SchedulingGroup buckets API keys that share the same resolved scheduling scope.
// Admin-only — regular users never see this view.
type SchedulingGroup struct {
	ID      string   `json:"id"`      // stable signature key
	Label   string   `json:"label"`   // human-readable name (pool name, "Global", or "custom")
	Members []string `json:"members"` // usernames in this group, sorted
}

// HandleSchedulingGroups returns API keys bucketed by their scheduling scope.
// Admin only. GET /api/scheduling/groups
func (h *Handler) HandleSchedulingGroups(w http.ResponseWriter, r *http.Request) {
	if !h.requireAdmin(w, r) {
		return
	}

	scopes, err := h.cfg.BuildSchedulingScopes()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve scheduling scopes: "+err.Error())
		return
	}

	// Bucket API keys by scope signature.
	buckets := map[string][]string{}
	for _, k := range h.cfg.APIKeys {
		if k.Name == "" {
			continue
		}
		scope := scopes[k.Name]
		sig := scope.Signature()
		buckets[sig] = append(buckets[sig], k.Name)
	}

	// Build pool-signature → name index so we can label groups that happen
	// to match a configured pool's expansion exactly.
	poolSignatures := map[string]string{}
	for _, p := range h.cfg.Pools {
		pseudo := &config.ResolvedScope{AllowedOwners: map[string]bool{}}
		for _, m := range p.Members {
			if m = strings.TrimSpace(m); m != "" {
				pseudo.AllowedOwners[m] = true
			}
		}
		poolSignatures[pseudo.Signature()] = p.Name
	}

	groups := make([]SchedulingGroup, 0, len(buckets))
	for sig, members := range buckets {
		sort.Strings(members)
		label := "custom"
		switch {
		case sig == "*":
			label = "Global"
		case sig == "(empty)":
			label = "Isolated"
		default:
			if name, ok := poolSignatures[sig]; ok {
				label = name
			}
		}
		groups = append(groups, SchedulingGroup{
			ID:      sig,
			Label:   label,
			Members: members,
		})
	}

	// Deterministic order: Global first, then alphabetic.
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Label == "Global" {
			return true
		}
		if groups[j].Label == "Global" {
			return false
		}
		return groups[i].Label < groups[j].Label
	})

	writeJSON(w, map[string]any{"groups": groups})
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

	if _, ok := h.requireOwner(w, r, req.Account); !ok {
		return
	}

	if !h.isOAuthAccount(req.Account) {
		writeError(w, http.StatusBadRequest, "account not found or not oauth")
		return
	}

	sessionID, authURL, err := h.sessions.Create(req.Account)
	if err != nil {
		slog.Error("oauth: failed to create PKCE session", "account_id", req.Account, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	slog.Info("oauth: login started", "account", h.accountDisplayName(req.Account), "account_id", req.Account, "session_id", sessionID)
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
		slog.Warn("oauth: login complete failed", "reason", "session_expired_or_missing", "session_id", req.SessionID)
		writeError(w, http.StatusBadRequest, "session not found or expired")
		return
	}

	if _, ownerOK := h.requireOwner(w, r, session.AccountID); !ownerOK {
		return
	}

	// Validate OAuth state parameter to prevent CSRF.
	// The code field may contain "authcode#state" (state appended by frontend).
	codeState := ""
	if idx := strings.Index(req.Code, "#"); idx != -1 {
		codeState = req.Code[idx+1:]
	}
	if subtle.ConstantTimeCompare([]byte(session.State), []byte(codeState)) != 1 {
		slog.Warn("oauth: login complete failed", "reason", "state_mismatch", "account_id", session.AccountID, "session_id", req.SessionID)
		h.sessions.Delete(req.SessionID)
		writeError(w, http.StatusBadRequest, "invalid OAuth state parameter")
		return
	}

	// Exchange code for token (pass full code with #state so provider sends state to Anthropic)
	slog.Info("oauth: completing login", "account_id", session.AccountID, "session_id", req.SessionID)
	proxyURL := h.registry.GetProxy(session.AccountID)
	token, err := h.oauthMgr.ExchangeAndSave(r.Context(), session.AccountID, req.Code, session.Verifier, proxyURL)
	if err != nil {
		slog.Error("oauth: login code exchange failed",
			"account_id", session.AccountID,
			"error", err.Error(),
		)
		writeError(w, http.StatusBadRequest, "code exchange failed: "+err.Error())
		return
	}

	h.sessions.Delete(req.SessionID)

	// Auto re-enable if account was disabled (including platform ban).
	// A successful OAuth login proves the account is valid again.
	if health := h.balancer.GetHealth(session.AccountID); health != nil {
		if health.IsDisabled() {
			if health.Enable() {
				slog.Info("oauth: account re-enabled after login",
					"account_id", session.AccountID,
				)
				if err := h.balancer.SaveState(h.dataDir); err != nil {
					slog.Warn("failed to persist health state after auto re-enable", "error", err)
				}
			}
		}
	}

	slog.Info("oauth: login complete",
		"account_id", session.AccountID,
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

	if _, ok := h.requireOwnerOrAdmin(w, r, req.Account); !ok {
		return
	}

	if !h.isOAuthAccount(req.Account) {
		writeError(w, http.StatusBadRequest, "account not found or not oauth")
		return
	}

	slog.Info("oauth: manual refresh requested", "account", h.accountDisplayName(req.Account), "account_id", req.Account)
	newToken, err := h.oauthMgr.ForceRefresh(r.Context(), req.Account)
	if err != nil {
		slog.Error("oauth: manual refresh failed", "account_id", req.Account, "error", err.Error())
		writeError(w, http.StatusBadRequest, "refresh failed: "+err.Error())
		return
	}

	slog.Info("oauth: manual refresh success",
		"account", h.accountDisplayName(req.Account),
		"account_id", req.Account,
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

	if _, ok := h.requireOwnerOrAdmin(w, r, req.Account); !ok {
		return
	}

	if err := h.oauthMgr.Logout(req.Account); err != nil {
		slog.Error("oauth: logout failed to delete token", "account_id", req.Account, "error", err.Error())
		writeError(w, http.StatusInternalServerError, "failed to delete token")
		return
	}

	slog.Info("oauth: logout success", "account", h.accountDisplayName(req.Account), "account_id", req.Account)
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

// isOAuthAccount checks if the given ID is a configured account.
func (h *Handler) isOAuthAccount(id string) bool {
	return h.registry.Has(id)
}

// accountDisplayName resolves an account ID to its display name for logging.
func (h *Handler) accountDisplayName(id string) string {
	if acct, ok := h.registry.GetByID(id); ok {
		return acct.Name
	}
	return id
}

// requireUser checks that the request is from a non-admin user.
// Admin is read-only and cannot mutate accounts. Returns the username or writes 403.
func (h *Handler) requireUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	auth := GetAdminAuth(r.Context())
	if auth == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return "", false
	}
	if auth.IsAdmin {
		writeError(w, http.StatusForbidden, "admin is read-only, cannot modify accounts")
		return "", false
	}
	return auth.Username, true
}

// requireOwner checks that the request is from the owner of the given account.
// Returns the username or writes an error response.
func (h *Handler) requireOwner(w http.ResponseWriter, r *http.Request, accountID string) (string, bool) {
	username, ok := h.requireUser(w, r)
	if !ok {
		return "", false
	}
	if !h.registry.IsOwner(accountID, username) {
		writeError(w, http.StatusForbidden, "you do not own this account")
		return "", false
	}
	return username, true
}

// requireOwnerOrAdmin checks that the request is from the account owner or admin.
// Admin can operate on any account; regular users can only operate on their own.
func (h *Handler) requireOwnerOrAdmin(w http.ResponseWriter, r *http.Request, accountID string) (string, bool) {
	auth := GetAdminAuth(r.Context())
	if auth == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return "", false
	}
	if auth.IsAdmin {
		return auth.Username, true
	}
	if !h.registry.IsOwner(accountID, auth.Username) {
		writeError(w, http.StatusForbidden, "you do not own this account")
		return "", false
	}
	return auth.Username, true
}

// requireAdmin checks that the request is from the admin user.
func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	auth := GetAdminAuth(r.Context())
	if auth == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return false
	}
	if !auth.IsAdmin {
		writeError(w, http.StatusForbidden, "admin only")
		return false
	}
	return true
}

// HandleAddAccount adds a new account to the registry.
// Only non-admin users can add accounts (owner is set to the requesting user).
// POST /api/accounts/add
func (h *Handler) HandleAddAccount(w http.ResponseWriter, r *http.Request) {
	username, ok := h.requireUser(w, r)
	if !ok {
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	newID, err := h.registry.Add(req.Name, username)
	if err != nil {
		slog.Warn("add account failed", "name", req.Name, "error", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Ensure the oauth manager knows about the new account.
	h.oauthMgr.UpdateAccounts(h.registry.IDs())

	slog.Info("account added", "name", req.Name, "id", newID)
	writeJSON(w, map[string]any{"ok": true, "id": newID})
}

// HandleRemoveAccount removes an account from the registry and cleans up its OAuth token.
// Admin or account owner can remove accounts.
// POST /api/accounts/remove
func (h *Handler) HandleRemoveAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if _, ok := h.requireOwnerOrAdmin(w, r, req.ID); !ok {
		return
	}

	// Clean up OAuth token before removing.
	if err := h.oauthMgr.Logout(req.ID); err != nil {
		slog.Warn("failed to delete oauth token on account removal", "id", req.ID, "error", err.Error())
	}

	if err := h.registry.Remove(req.ID); err != nil {
		slog.Warn("remove account failed", "id", req.ID, "error", err.Error())
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Update oauth manager account list.
	h.oauthMgr.UpdateAccounts(h.registry.IDs())

	slog.Info("account removed", "id", req.ID)
	writeJSON(w, map[string]bool{"ok": true})
}

// HandleUpdateProxy updates the proxy URL for an account.
// Admin or account owner can update proxy.
// POST /api/accounts/proxy
func (h *Handler) HandleUpdateProxy(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    string `json:"id"`
		Proxy string `json:"proxy"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if _, ok := h.requireOwnerOrAdmin(w, r, req.ID); !ok {
		return
	}

	if err := h.registry.UpdateProxy(req.ID, req.Proxy); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("account proxy updated", "id", req.ID, "proxy", req.Proxy)
	writeJSON(w, map[string]bool{"ok": true})
}

// HandleRenameAccount changes the display name of an account.
// POST /api/accounts/rename
func (h *Handler) HandleRenameAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if _, ok := h.requireOwnerOrAdmin(w, r, req.ID); !ok {
		return
	}

	if err := h.registry.Rename(req.ID, req.Name); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	slog.Info("account renamed", "id", req.ID, "name", req.Name)
	writeJSON(w, map[string]bool{"ok": true})
}

// testModel is the model used for account connectivity tests. Use a small,
// fast model to minimise cost and latency.
const testModel = "claude-haiku-4-5-20251001"

// HandleTestAccount sends a minimal API request using the account's
// OAuth token to verify the token and network path are working.
// POST /api/accounts/test
func (h *Handler) HandleTestAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if _, ok := h.requireOwnerOrAdmin(w, r, req.Account); !ok {
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

	// Build HTTP client with TLS fingerprint transport (required for OAuth to be accepted by
	// Anthropic — they reject OAuth tokens from non-CLI TLS fingerprints).
	httpClient := &http.Client{
		Timeout:   15 * time.Second,
		Transport: proxytls.NewTransport(),
	}

	// Inject per-account SOCKS5 proxy via context so fingerprintTransport picks it up.
	reqCtx := r.Context()
	if proxyURL := h.registry.GetProxy(req.Account); proxyURL != "" {
		reqCtx = proxytls.WithProxyURL(reqCtx, proxyURL)
	}

	body, _ := json.Marshal(map[string]any{
		"model":      testModel,
		"max_tokens": 50,
		"messages":   []map[string]string{{"role": "user", "content": "hi"}},
		"tools":      []any{},
		"metadata":   map[string]any{"user_id": "test-connectivity"},
	})

	apiReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost,
		"https://api.anthropic.com/v1/messages?beta=true", bytes.NewReader(body))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build request")
		return
	}
	// Apply full Claude CLI disguise headers so Anthropic accepts the OAuth token.
	disguise.ApplyHeaders(apiReq, false, nil)
	apiReq.Header["anthropic-beta"] = []string{disguise.BetaHeader(testModel, false)}
	apiReq.Header.Set("Authorization", "Bearer "+token.AccessToken)
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

// HandleAccountEnable re-enables a disabled account.
// POST /api/accounts/enable
func (h *Handler) HandleAccountEnable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decodeBody(w, r, &req) {
		return
	}

	if _, ok := h.requireOwnerOrAdmin(w, r, req.Account); !ok {
		return
	}

	health := h.balancer.GetHealth(req.Account)
	if health == nil {
		writeError(w, http.StatusBadRequest, "account not found")
		return
	}

	if !health.IsDisabled() {
		writeError(w, http.StatusBadRequest, "account is not disabled")
		return
	}

	if health.Enable() {
		slog.Info("account re-enabled via admin", "account", h.accountDisplayName(req.Account), "account_id", req.Account)
		if err := h.balancer.SaveState(h.dataDir); err != nil {
			slog.Warn("failed to persist health state after enable", "error", err)
		}
		writeJSON(w, map[string]any{"ok": true})
	} else {
		writeError(w, http.StatusInternalServerError, "failed to enable account")
	}
}
