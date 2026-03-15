package loadbalancer

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/binn/ccproxy/internal/fileutil"
)

const (
	stateFileName  = "health_state.json"
	stateMaxAge    = 24 * time.Hour
	persistTicker  = 5 * time.Minute
	statePerm      = 0600
)

// PersistedState is the file-level structure for health state.
type PersistedState struct {
	Accounts  map[string]*PersistedAccount `json:"accounts"`
	UpdatedAt time.Time                     `json:"updated_at"`
}

// PersistedAccount holds the persisted health fields for one account.
type PersistedAccount struct {
	Disabled       bool    `json:"disabled"`
	DisabledReason string  `json:"disabled_reason,omitempty"`
	Utilization5h  float64 `json:"utilization_5h,omitempty"`
	Utilization7d  float64 `json:"utilization_7d,omitempty"`
}

// SaveState atomically writes health state to dataDir/health_state.json.
func SaveState(dataDir string, health map[string]*AccountHealth) error {
	state := &PersistedState{
		Accounts:  make(map[string]*PersistedAccount, len(health)),
		UpdatedAt: time.Now(),
	}
	for name, h := range health {
		h.mu.RLock()
		pa := &PersistedAccount{
			Disabled:       h.disabled,
			DisabledReason: h.disabledReason,
		}
		h.mu.RUnlock()

		// Persist budget utilization
		if h.budget != nil {
			w5 := h.budget.Window5h()
			w7 := h.budget.Window7d()
			pa.Utilization5h = w5.Utilization
			pa.Utilization7d = w7.Utilization
		}

		state.Accounts[name] = pa
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	path := filepath.Join(dataDir, stateFileName)
	return fileutil.AtomicWriteFile(path, data, statePerm)
}

// LoadState reads health state from file. Returns nil if missing, corrupt, or stale.
func LoadState(dataDir string) *PersistedState {
	path := filepath.Join(dataDir, stateFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("health: failed to read state file", "path", path, "error", err.Error())
		}
		return nil
	}
	var state PersistedState
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Warn("health: corrupted state file, ignoring", "path", path, "error", err.Error())
		return nil
	}
	age := time.Since(state.UpdatedAt)
	if age > stateMaxAge {
		slog.Info("health: state file too old, ignoring", "age", age.String(), "max_age", stateMaxAge.String())
		return nil
	}
	slog.Info("health: loaded persisted state", "accounts", len(state.Accounts), "age", age.String())
	return &state
}

// ApplyState restores persisted values into the health map.
func ApplyState(health map[string]*AccountHealth, state *PersistedState) {
	if state == nil {
		return
	}
	for name, pa := range state.Accounts {
		h, ok := health[name]
		if !ok {
			continue
		}
		if pa.Disabled {
			h.Disable(pa.DisabledReason)
		}
		// Restore budget utilization as initial estimates
		if h.budget != nil && (pa.Utilization5h > 0 || pa.Utilization7d > 0) {
			h.budget.UpdateFromUsageAPI(
				UsageAPIWindow{Utilization: pa.Utilization5h * 100}, // convert back to 0-100
				UsageAPIWindow{Utilization: pa.Utilization7d * 100},
			)
		}
	}
}

// StartPersistence starts a background goroutine that saves state periodically.
func (b *Balancer) StartPersistence(ctx context.Context, dataDir string) {
	go func() {
		ticker := time.NewTicker(persistTicker)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := b.SaveState(dataDir); err != nil {
					slog.Error("health: failed to persist state", "error", err.Error())
				}
			}
		}
	}()
}

// SaveState writes current health state to disk.
func (b *Balancer) SaveState(dataDir string) error {
	b.mu.RLock()
	health := b.health
	b.mu.RUnlock()
	return SaveState(dataDir, health)
}

// LoadState restores health state from disk.
func (b *Balancer) LoadState(dataDir string) {
	state := LoadState(dataDir)
	if state == nil {
		return
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	ApplyState(b.health, state)
}
