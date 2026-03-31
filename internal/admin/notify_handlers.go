package admin

import (
	"net/http"
	"strings"

	"github.com/binn/ccproxy/internal/notify"
)

// HandleNotifyConfig handles GET and POST /api/notify/config.
// GET returns the current config with bot_token masked.
// POST saves the config and reinitializes the global Notifier.
func (h *Handler) HandleNotifyConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := notify.LoadConfig(h.dataDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "load config: "+err.Error())
			return
		}
		masked := cfg
		masked.BotToken = maskToken(cfg.BotToken)
		writeJSON(w, masked)

	case http.MethodPost:
		var body notify.NotifyConfig
		if !decodeBody(w, r, &body) {
			return
		}
		// Preserve existing token when the user submits the masked placeholder.
		if strings.HasPrefix(body.BotToken, "****") {
			existing, err := notify.LoadConfig(h.dataDir)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "load existing config: "+err.Error())
				return
			}
			body.BotToken = existing.BotToken
		}
		if err := notify.SaveConfig(h.dataDir, body); err != nil {
			writeError(w, http.StatusInternalServerError, "save config: "+err.Error())
			return
		}
		if body.BotToken != "" && body.ChatID != "" {
			notify.SetGlobal(notify.NewTelegramNotifier(body))
		} else {
			notify.SetGlobal(&notify.NoopNotifier{})
		}
		writeJSON(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleNotifyTest handles POST /api/notify/test.
// Sends a test Telegram message using the current saved config.
func (h *Handler) HandleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, err := notify.LoadConfig(h.dataDir)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load config: "+err.Error())
		return
	}
	if cfg.BotToken == "" || cfg.ChatID == "" {
		writeError(w, http.StatusBadRequest, "telegram not configured")
		return
	}
	// Fresh notifier with both categories enabled — test bypasses category filter
	// to verify connectivity regardless of user's category preferences.
	testCfg := cfg
	testCfg.EnableDisabled = true
	testCfg.EnableAnomaly = true
	n := notify.NewTelegramNotifier(testCfg)
	if err := n.Notify(r.Context(), notify.Event{
		AccountName: "test",
		Type:        notify.EventAccountDisabled,
		Detail:      "this is a test notification from ccproxy admin",
	}); err != nil {
		writeError(w, http.StatusBadGateway, "telegram send failed: "+err.Error())
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

// maskToken returns the token with all but the last 4 characters replaced by ****.
func maskToken(token string) string {
	if token == "" {
		return ""
	}
	if len(token) <= 4 {
		return strings.Repeat("*", len(token))
	}
	return "****" + token[len(token)-4:]
}
