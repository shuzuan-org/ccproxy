package admin

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/binn/ccproxy/internal/loadbalancer"
	"github.com/binn/ccproxy/internal/observability"
)

//go:embed static
var staticFiles embed.FS

// Handler provides HTTP handlers for the admin dashboard.
type Handler struct {
	stats    *observability.Stats
	balancer *loadbalancer.Balancer
}

// NewHandler creates an admin Handler.
func NewHandler(stats *observability.Stats, balancer *loadbalancer.Balancer) *Handler {
	return &Handler{
		stats:    stats,
		balancer: balancer,
	}
}

// writeJSON writes v as JSON with Content-Type: application/json.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "json encode error", http.StatusInternalServerError)
	}
}

// HandleStats returns token usage statistics grouped by instance.
// GET /api/stats?hours=24
func (h *Handler) HandleStats(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			hours = n
		}
	}

	usage, err := h.stats.TokenUsageByInstance(hours)
	if err != nil {
		http.Error(w, "failed to query stats: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if usage == nil {
		usage = []observability.InstanceUsage{}
	}
	writeJSON(w, usage)
}

// InstanceState holds the runtime state of a single backend instance.
type InstanceState struct {
	Name           string `json:"name"`
	AuthMode       string `json:"auth_mode"`
	LoadRate       int    `json:"load_rate"`
	ActiveSlots    int    `json:"active_slots"`
	MaxConcurrency int    `json:"max_concurrency"`
	Priority       int    `json:"priority"`
	Enabled        bool   `json:"enabled"`
}

// HandleInstances returns instance health status and load info.
// GET /api/instances
func (h *Handler) HandleInstances(w http.ResponseWriter, r *http.Request) {
	instances := h.balancer.GetInstances()
	tracker := h.balancer.GetTracker()

	states := make([]InstanceState, 0, len(instances))
	for _, inst := range instances {
		active, _, rate := tracker.LoadInfo(inst.Name, inst.MaxConcurrency)
		states = append(states, InstanceState{
			Name:           inst.Name,
			AuthMode:       inst.AuthMode,
			LoadRate:       rate,
			ActiveSlots:    active,
			MaxConcurrency: inst.MaxConcurrency,
			Priority:       inst.Priority,
			Enabled:        inst.IsEnabled(),
		})
	}
	writeJSON(w, states)
}

// SessionState holds minimal info about an active sticky session.
type SessionState struct {
	SessionKey   string `json:"session_key"`
	InstanceName string `json:"instance_name"`
}

// HandleSessions returns active session list.
// GET /api/sessions
func (h *Handler) HandleSessions(w http.ResponseWriter, r *http.Request) {
	// Balancer does not expose individual session details; return empty list.
	writeJSON(w, []SessionState{})
}

// HandleRequests returns recent request logs.
// GET /api/requests?limit=100
func (h *Handler) HandleRequests(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	records, err := h.stats.RecentRequests(limit)
	if err != nil {
		http.Error(w, "failed to query requests: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if records == nil {
		records = []observability.RequestRecord{}
	}
	writeJSON(w, records)
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
