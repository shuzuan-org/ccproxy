package admin

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"

	"github.com/binn/ccproxy/internal/loadbalancer"
)

//go:embed static
var staticFiles embed.FS

// Handler provides HTTP handlers for the admin dashboard.
type Handler struct {
	balancer *loadbalancer.Balancer
}

// NewHandler creates an admin Handler.
func NewHandler(balancer *loadbalancer.Balancer) *Handler {
	return &Handler{
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

// HandleDashboard serves the embedded static HTML dashboard.
// GET /admin/*
func (h *Handler) HandleDashboard() http.Handler {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic("admin: failed to sub static fs: " + err.Error())
	}
	return http.FileServer(http.FS(sub))
}
