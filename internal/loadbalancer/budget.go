package loadbalancer

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/notify"
	"github.com/binn/ccproxy/internal/observe"
)

// SchedulingState represents three-level scheduling status for an account.
type SchedulingState int

const (
	StateNormal     SchedulingState = iota // utilization below warning threshold
	StateStickyOnly                        // only serve sticky sessions
	StateBlocked                           // do not schedule any requests
)

func (s SchedulingState) String() string {
	switch s {
	case StateNormal:
		return "normal"
	case StateStickyOnly:
		return "sticky_only"
	case StateBlocked:
		return "blocked"
	default:
		return "unknown"
	}
}

const (
	defaultNormalThreshold  = 0.90 // below this → Normal
	defaultDangerThreshold  = 0.95 // at or above this → Blocked; between normal and danger → StickyOnly
	penaltyStep             = 0.03 // per consecutive true 429
	penaltyMax              = 0.15 // maximum penalty shift
	penaltyRecoveryInterval = 5 * time.Minute
)

// BudgetWindow holds rate-limit state for a single time window (5h or 7d).
type BudgetWindow struct {
	Utilization float64   // 0-1 normalized
	ResetAt     time.Time // when the window resets
	Status      string    // "allowed", "allowed_warning", "rejected"
	LastUpdated time.Time
}

// BudgetController tracks dual-window (5h/7d) rate-limit budget for one account.
type BudgetController struct {
	name           string // account name for logging
	mu             sync.RWMutex
	window5h       BudgetWindow
	window7d       BudgetWindow
	consecutive429 int
	lastPenaltyAt  time.Time
	penaltyShift   float64 // threshold shift down per consecutive 429
	lastSuccessAt  time.Time
	lastState      SchedulingState // cached for state-change detection
}

// NewBudgetController creates a new budget controller for the named account.
func NewBudgetController(name string) *BudgetController {
	return &BudgetController{name: name}
}

// UpdateFromHeaders parses anthropic-ratelimit-unified-* response headers.
// Header format: anthropic-ratelimit-unified-{5h,7d}-{utilization,status,reset}
// Utilization values from headers are 0-1 decimals.
func (bc *BudgetController) UpdateFromHeaders(ctx context.Context, headers http.Header) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	now := time.Now()

	// Parse 5h window
	if v := headers.Get("anthropic-ratelimit-unified-5h-utilization"); v != "" {
		if u, err := strconv.ParseFloat(v, 64); err == nil {
			bc.window5h.Utilization = clamp01(u)
			bc.window5h.LastUpdated = now
		}
	}
	if v := headers.Get("anthropic-ratelimit-unified-5h-status"); v != "" {
		bc.window5h.Status = strings.TrimSpace(v)
		bc.window5h.LastUpdated = now
	}
	if v := headers.Get("anthropic-ratelimit-unified-5h-reset"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			bc.window5h.ResetAt = t
			bc.window5h.LastUpdated = now
		}
	}

	// Parse 7d window
	if v := headers.Get("anthropic-ratelimit-unified-7d-utilization"); v != "" {
		if u, err := strconv.ParseFloat(v, 64); err == nil {
			bc.window7d.Utilization = clamp01(u)
			bc.window7d.LastUpdated = now
		}
	}
	if v := headers.Get("anthropic-ratelimit-unified-7d-status"); v != "" {
		bc.window7d.Status = strings.TrimSpace(v)
		bc.window7d.LastUpdated = now
	}
	if v := headers.Get("anthropic-ratelimit-unified-7d-reset"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			bc.window7d.ResetAt = t
			bc.window7d.LastUpdated = now
		}
	}

	observe.Logger(ctx).Debug("budget: headers updated",
		"account", bc.name,
		"util_5h", bc.window5h.Utilization,
		"util_7d", bc.window7d.Utilization,
		"state", bc.stateLocked().String(),
	)
	bc.checkStateChange(ctx)
}

// UsageAPIWindow represents a single window from the usage API response.
type UsageAPIWindow struct {
	Utilization float64 // 0-100 from API
	ResetsAt    string  // RFC3339
}

// UpdateFromUsageAPI updates budget from usage API data.
// API returns utilization as 0-100; this normalizes to 0-1.
func (bc *BudgetController) UpdateFromUsageAPI(fiveHour, sevenDay UsageAPIWindow) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	now := time.Now()

	bc.window5h.Utilization = clamp01(fiveHour.Utilization / 100.0)
	bc.window5h.LastUpdated = now
	if t, err := time.Parse(time.RFC3339, fiveHour.ResetsAt); err == nil {
		bc.window5h.ResetAt = t
	}

	bc.window7d.Utilization = clamp01(sevenDay.Utilization / 100.0)
	bc.window7d.LastUpdated = now
	if t, err := time.Parse(time.RFC3339, sevenDay.ResetsAt); err == nil {
		bc.window7d.ResetAt = t
	}

	slog.Debug("budget: usage API updated",
		"account", bc.name,
		"util_5h", bc.window5h.Utilization,
		"util_7d", bc.window7d.Utilization,
		"state", bc.stateLocked().String(),
	)
}

// State returns the scheduling state based on the worse of the two windows.
func (bc *BudgetController) State() SchedulingState {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.stateLocked()
}

func (bc *BudgetController) stateLocked() SchedulingState {
	maxUtil := math.Max(bc.window5h.Utilization, bc.window7d.Utilization)
	normalThresh := defaultNormalThreshold - bc.penaltyShift
	dangerThresh := defaultDangerThreshold - bc.penaltyShift
	if maxUtil >= dangerThresh {
		return StateBlocked
	}
	if maxUtil >= normalThresh {
		return StateStickyOnly
	}
	return StateNormal
}

// checkStateChange logs when state transitions. Must be called with bc.mu held.
func (bc *BudgetController) checkStateChange(ctx context.Context) {
	current := bc.stateLocked()
	if current != bc.lastState {
		observe.Logger(ctx).Info("budget: state changed",
			"account", bc.name,
			"from", bc.lastState.String(),
			"to", current.String(),
		)
		bc.lastState = current
		if current == StateBlocked {
			name := bc.name
			util5h := bc.window5h.Utilization
			util7d := bc.window7d.Utilization
			go func() {
				_ = notify.Global().Notify(ctx, notify.Event{
					AccountName: name,
					Type:        notify.EventBudgetBlocked,
					Detail:      fmt.Sprintf("util_5h=%.0f%%, util_7d=%.0f%%", util5h*100, util7d*100),
				})
			}()
		}
	}
}

// MaxUtilization returns max(5h.Utilization, 7d.Utilization).
func (bc *BudgetController) MaxUtilization() float64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return math.Max(bc.window5h.Utilization, bc.window7d.Utilization)
}

// Record429 records a 429 response. hasResetHeaders indicates whether
// the response included anthropic-ratelimit reset headers (true 429 vs fake).
func (bc *BudgetController) Record429(ctx context.Context, hasResetHeaders bool) {
	if !hasResetHeaders {
		return // fake 429, don't adjust thresholds
	}
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.consecutive429++
	bc.lastPenaltyAt = time.Now()
	bc.penaltyShift += penaltyStep
	if bc.penaltyShift > penaltyMax {
		bc.penaltyShift = penaltyMax
	}
	observe.Logger(ctx).Warn("budget: 429 recorded",
		"account", bc.name,
		"true_429", hasResetHeaders,
		"consecutive", bc.consecutive429,
		"penalty", bc.penaltyShift,
	)
	bc.checkStateChange(ctx)
}

// RecordSuccess records a successful request. If enough time has passed
// since the last 429, gradually recovers the threshold penalty.
func (bc *BudgetController) RecordSuccess(ctx context.Context) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.lastSuccessAt = time.Now()
	if bc.consecutive429 > 0 && time.Since(bc.lastPenaltyAt) > penaltyRecoveryInterval {
		bc.consecutive429--
		bc.penaltyShift -= penaltyStep
		if bc.penaltyShift < 0 {
			bc.penaltyShift = 0
		}
		bc.lastPenaltyAt = time.Now() // reset timer for next step
		observe.Logger(ctx).Info("budget: penalty recovered",
			"account", bc.name,
			"penalty", bc.penaltyShift,
		)
		bc.checkStateChange(ctx)
	}
}

// DynamicMaxConcurrency calculates adaptive concurrency based on utilization.
// Returns a value between 1 and hardLimit.
func (bc *BudgetController) DynamicMaxConcurrency(hardLimit int) int {
	bc.mu.RLock()
	maxUtil := math.Max(bc.window5h.Utilization, bc.window7d.Utilization)
	bc.mu.RUnlock()

	var dynamic int
	switch {
	case maxUtil < 0.5:
		dynamic = 8
	case maxUtil < 0.7:
		dynamic = 5
	case maxUtil < 0.85:
		dynamic = 3
	default:
		dynamic = 1
	}

	if hardLimit > 0 && dynamic > hardLimit {
		dynamic = hardLimit
	}
	if dynamic < 1 {
		dynamic = 1
	}
	if dynamic != hardLimit {
		slog.Debug("budget: dynamic concurrency adjusted",
			"account", bc.name,
			"default_max", hardLimit,
			"effective_max", dynamic,
			"max_util", maxUtil,
		)
	}
	return dynamic
}

// HasRecentData returns true if either window was updated within the given duration.
func (bc *BudgetController) HasRecentData(within time.Duration) bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	cutoff := time.Now().Add(-within)
	return bc.window5h.LastUpdated.After(cutoff) || bc.window7d.LastUpdated.After(cutoff)
}

// CooldownUntil returns the latest reset time from headers, useful for true 429 cooldown.
func (bc *BudgetController) CooldownUntil() time.Time {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	if bc.window5h.ResetAt.After(bc.window7d.ResetAt) {
		return bc.window5h.ResetAt
	}
	return bc.window7d.ResetAt
}

// Window5h returns a snapshot of the 5-hour window.
func (bc *BudgetController) Window5h() BudgetWindow {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.window5h
}

// Window7d returns a snapshot of the 7-day window.
func (bc *BudgetController) Window7d() BudgetWindow {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.window7d
}

// PenaltyShift returns the current threshold penalty shift.
func (bc *BudgetController) PenaltyShift() float64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.penaltyShift
}

// Consecutive429 returns the consecutive true 429 count.
func (bc *BudgetController) Consecutive429() int {
	bc.mu.RLock()
	defer bc.mu.RUnlock()
	return bc.consecutive429
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// EffectiveMaxConcurrency computes the dynamic max concurrency for an account.
// If budget is nil or has no data, returns the hardLimit as-is.
func EffectiveMaxConcurrency(budget *BudgetController, hardLimit int) int {
	if budget == nil {
		return hardLimit
	}
	return budget.DynamicMaxConcurrency(hardLimit)
}
