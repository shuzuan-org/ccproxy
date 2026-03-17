package admin

import (
	"net/http"
	"time"

	"github.com/binn/ccproxy/internal/updater"
)

// HandleUpdateStatus returns the current update status.
func (h *Handler) HandleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.updater == nil {
		writeJSON(w, updater.UpdateStatus{})
		return
	}

	writeJSON(w, h.updater.Status())
}

// HandleUpdateCheck triggers an immediate version check.
func (h *Handler) HandleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.updater == nil {
		writeError(w, http.StatusServiceUnavailable, "updater not available")
		return
	}

	latest, err := h.updater.CheckNow(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]string{"latest": latest})
}

// HandleUpdateApply triggers an immediate upgrade.
func (h *Handler) HandleUpdateApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.updater == nil {
		writeError(w, http.StatusServiceUnavailable, "updater not available")
		return
	}

	if h.updater.IsDocker() {
		writeError(w, http.StatusServiceUnavailable, "update not supported in Docker")
		return
	}

	updated, newVer, err := h.updater.Apply(r.Context(), false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, map[string]any{
		"updated":     updated,
		"new_version": newVer,
	})

	if updated {
		// Flush response before restart to ensure client receives it.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		go func() {
			time.Sleep(200 * time.Millisecond)
			h.updater.Restart()
		}()
	}
}
