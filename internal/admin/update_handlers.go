package admin

import (
	"encoding/json"
	"net/http"

	"github.com/binn/ccproxy/internal/updater"
)

// HandleUpdateStatus returns the current update status.
func (h *Handler) HandleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if h.updater == nil {
		json.NewEncoder(w).Encode(updater.UpdateStatus{})
		return
	}

	json.NewEncoder(w).Encode(h.updater.Status())
}

// HandleUpdateCheck triggers an immediate version check.
func (h *Handler) HandleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.updater == nil {
		http.Error(w, "updater not available", http.StatusServiceUnavailable)
		return
	}

	latest, err := h.updater.CheckNow(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"latest": latest})
}

// HandleUpdateApply triggers an immediate upgrade.
func (h *Handler) HandleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.updater == nil {
		http.Error(w, "updater not available", http.StatusServiceUnavailable)
		return
	}

	updated, newVer, err := h.updater.Apply(r.Context(), false)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"updated":     updated,
		"new_version": newVer,
	})

	if updated {
		go h.updater.Restart()
	}
}
