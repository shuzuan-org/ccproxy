package loadbalancer

import (
	"context"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/binn/ccproxy/internal/observe"
)

const (
	healthWindowSize   = 5 * time.Minute  // sliding window for error rate
	healthWindowMaxCap = 1000             // max entries per window slice
	cooldown429        = 30 * time.Second // default cooldown for 429 (fake, no reset headers)
	cooldown529        = 60 * time.Second // default cooldown for 529
	cooldown401        = 30 * time.Second // wait for token refresh
	cooldown401Disable = 5 * time.Minute  // disable threshold window for 401
	timeoutThreshold   = 3               // consecutive timeouts before cooldown
	auth401Threshold   = 3               // consecutive 401s before disable
)

// AccountHealth tracks dynamic health state for one account.
type AccountHealth struct {
	Name string

	// Budget controller for rate-limit tracking
	budget *BudgetController

	// Cooldown
	mu             sync.RWMutex
	cooldownUntil  time.Time
	cooldownReason string
	disabled       bool
	disabledReason string

	// Error tracking
	consecutive401  int
	first401At      time.Time
	timeoutCount    int
	firstTimeoutAt  time.Time
	consecutive529  int

	// Latency EMA (microseconds, lock-free CAS)
	latencyEMA  atomic.Int64 // slow α=0.1
	latencyFast atomic.Int64 // fast α=0.5

	// Cooldown recovery tracking (lock-free)
	wasCoolingDown       atomic.Bool
	lastCooldownDuration atomic.Int64 // stored as nanoseconds

	// Sliding window
	windowMu     sync.Mutex
	windowErrors []time.Time
	windowTotal  []time.Time
}

// NewAccountHealth creates a new health tracker for an account.
func NewAccountHealth(name string) *AccountHealth {
	return &AccountHealth{
		Name:   name,
		budget: NewBudgetController(name),
	}
}

// Budget returns the budget controller for this account.
func (h *AccountHealth) Budget() *BudgetController {
	return h.budget
}

// RecordSuccess updates health after a successful request.
func (h *AccountHealth) RecordSuccess(ctx context.Context, latencyUs int64) {
	h.updateLatency(latencyUs)
	h.recordWindow(false)
	h.budget.RecordSuccess(ctx)

	h.mu.Lock()
	h.consecutive401 = 0
	h.consecutive529 = 0
	h.timeoutCount = 0
	h.mu.Unlock()
}

// RecordError updates health after a failed request.
// responseHeaders may be nil for errors without response headers.
func (h *AccountHealth) RecordError(ctx context.Context, statusCode int, retryAfter time.Duration, responseHeaders http.Header) {
	switch statusCode {
	case 429:
		hasResetHeaders := false
		if responseHeaders != nil {
			hasResetHeaders = responseHeaders.Get("anthropic-ratelimit-unified-5h-reset") != "" ||
				responseHeaders.Get("anthropic-ratelimit-unified-7d-reset") != ""
		}

		if hasResetHeaders {
			// True 429: use reset time from headers as cooldown
			h.budget.Record429(ctx, true)
			h.budget.UpdateFromHeaders(ctx, responseHeaders)
			cooldownUntil := h.budget.CooldownUntil()
			cd := time.Until(cooldownUntil)
			if cd <= 0 {
				cd = cooldown429
			}
			observe.Logger(ctx).Warn("account rate limited (true 429)", "account", h.Name, "cooldown", cd.String())
			h.setCooldownWithTracking(cd, "rate_limited")
			h.recordWindow(true)
		} else {
			// Fake 429: short cooldown, don't affect budget or SRE
			h.budget.Record429(ctx, false)
			observe.Logger(ctx).Warn("account rate limited (no reset headers)", "account", h.Name, "cooldown", "5s")
			h.setCooldownWithTracking(5*time.Second, "rate_limited_soft")
			// Don't record in error window — not a real rate limit
		}

	case 529:
		jitter := time.Duration(rand.Int63n(int64(15 * time.Second)))
		cd := cooldown529 + jitter
		observe.Logger(ctx).Warn("account overloaded", "account", h.Name, "cooldown", cd.String())
		h.setCooldownWithTracking(cd, "overloaded")
		h.recordWindow(true)

		h.mu.Lock()
		h.consecutive529++
		h.mu.Unlock()

	case 401:
		observe.Logger(ctx).Warn("account auth error, cooling down", "account", h.Name, "cooldown", cooldown401.String())
		h.setCooldownWithTracking(cooldown401, "auth_refresh")

		h.mu.Lock()
		now := time.Now()
		if h.consecutive401 == 0 {
			h.first401At = now
		}
		h.consecutive401++
		if h.consecutive401 >= auth401Threshold && now.Sub(h.first401At) < cooldown401Disable {
			h.mu.Unlock()
			observe.Logger(ctx).Error("account disabled: too many consecutive 401s", "account", h.Name, "count", auth401Threshold)
			h.Disable("consecutive_401")
		} else {
			h.mu.Unlock()
		}

	case 403:
		observe.Logger(ctx).Error("account forbidden, disabling", "account", h.Name)
		h.Disable(legacyBanReasonForbidden)

	case 400:
		// 400 with "organization disabled" text handled by caller via body check
		h.recordWindow(true)

	default:
		if statusCode >= 500 && statusCode <= 504 {
			// Server errors: record but don't cool down, don't affect budget
			h.recordWindow(true)
		}
	}
}

// RecordTimeout records a request timeout.
func (h *AccountHealth) RecordTimeout(ctx context.Context) {
	h.mu.Lock()
	now := time.Now()
	if h.timeoutCount == 0 {
		h.firstTimeoutAt = now
	}
	h.timeoutCount++
	if h.timeoutCount >= timeoutThreshold && now.Sub(h.firstTimeoutAt) < healthWindowSize {
		h.mu.Unlock()
		observe.Logger(ctx).Warn("account cooldown: timeout threshold reached", "account", h.Name, "count", h.timeoutCount)
		h.setCooldownWithTracking(2*time.Minute, "timeout_threshold")
		return
	}
	h.mu.Unlock()
}

// Consecutive529 returns the consecutive 529 count.
func (h *AccountHealth) Consecutive529() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.consecutive529
}

// ResetConsecutive401 resets the 401 counter on successful auth.
func (h *AccountHealth) ResetConsecutive401() {
	h.mu.Lock()
	h.consecutive401 = 0
	h.mu.Unlock()
}

// IsAvailable returns true if the account is not disabled and not in cooldown.
func (h *AccountHealth) IsAvailable() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.disabled {
		return false
	}
	available := time.Now().After(h.cooldownUntil) || h.cooldownUntil.IsZero()
	if available && h.wasCoolingDown.CompareAndSwap(true, false) {
		slog.Info("account recovered from cooldown",
			"account", h.Name,
			"cooldown_duration", time.Duration(h.lastCooldownDuration.Load()),
		)
	}
	return available
}

// ScoreBreakdown holds the individual components of a composite score.
type ScoreBreakdown struct {
	Score        float64
	ErrRate      float64
	LatencyScore float64
	LoadRate     float64
	MaxUtil      float64
}

// Score computes a composite score (lower is better).
// score = errorRate*0.3 + normalizedLatency*0.2 + loadRate/100*0.2 + maxUtil*0.3
func (h *AccountHealth) Score(loadRate int) float64 {
	return h.ScoreDetail(loadRate).Score
}

// ScoreDetail computes a composite score and returns the breakdown of each component.
func (h *AccountHealth) ScoreDetail(loadRate int) ScoreBreakdown {
	errRate := h.ErrorRate()

	// Normalize latency: use fast EMA relative to slow EMA.
	// If slow is 0 (cold start), latency component is 0.
	slow := h.latencyEMA.Load()
	fast := h.latencyFast.Load()
	var normalizedLatency float64
	if slow > 0 {
		normalizedLatency = float64(fast) / float64(slow)
		if normalizedLatency > 2.0 {
			normalizedLatency = 2.0
		}
		normalizedLatency /= 2.0 // scale to 0-1
	}

	maxUtil := h.budget.MaxUtilization()
	lr := float64(loadRate) / 100.0

	return ScoreBreakdown{
		Score:        errRate*0.3 + normalizedLatency*0.2 + lr*0.2 + maxUtil*0.3,
		ErrRate:      errRate,
		LatencyScore: normalizedLatency,
		LoadRate:     lr,
		MaxUtil:      maxUtil,
	}
}

// ErrorRate returns the error rate in the sliding window.
func (h *AccountHealth) ErrorRate() float64 {
	h.windowMu.Lock()
	defer h.windowMu.Unlock()

	cutoff := time.Now().Add(-healthWindowSize)
	h.windowErrors = pruneWindow(h.windowErrors, cutoff)
	h.windowTotal = pruneWindow(h.windowTotal, cutoff)

	total := len(h.windowTotal)
	if total == 0 {
		return 0
	}
	return float64(len(h.windowErrors)) / float64(total)
}

// SetCooldown sets a cooldown period with a reason.
func (h *AccountHealth) SetCooldown(d time.Duration, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cooldownUntil = time.Now().Add(d)
	h.cooldownReason = reason
}

// setCooldownWithTracking sets a cooldown and records tracking for recovery logging.
func (h *AccountHealth) setCooldownWithTracking(d time.Duration, reason string) {
	h.wasCoolingDown.Store(true)
	h.lastCooldownDuration.Store(int64(d))
	h.SetCooldown(d, reason)
}

// Disable permanently disables this account.
func (h *AccountHealth) Disable(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disabled = true
	h.disabledReason = reason
}

// IsDisabled returns whether the account is permanently disabled.
func (h *AccountHealth) IsDisabled() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.disabled
}

// DisabledReason returns the reason for disabling.
func (h *AccountHealth) DisabledReason() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.disabledReason
}

// IsBanned returns whether the account was disabled due to a platform ban.
func (h *AccountHealth) IsBanned() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return IsPlatformBanReason(h.disabledReason)
}

// BanReason returns the normalized platform ban reason.
func (h *AccountHealth) BanReason() string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	switch h.disabledReason {
	case legacyBanReasonForbidden:
		return PlatformBanReasonForbidden
	case PlatformBanReasonForbidden,
		PlatformBanReasonOAuthNotAllowed,
		PlatformBanReasonOrganizationDisabled:
		return h.disabledReason
	default:
		return ""
	}
}

// LatencyEMA returns the slow EMA latency in microseconds.
func (h *AccountHealth) LatencyEMA() int64 {
	return h.latencyEMA.Load()
}

func (h *AccountHealth) updateLatency(us int64) {
	// Slow EMA α=0.1
	for {
		old := h.latencyEMA.Load()
		if old == 0 {
			if h.latencyEMA.CompareAndSwap(0, us) {
				h.latencyFast.Store(us)
				return
			}
			continue
		}
		newSlow := (us + 9*old) / 10
		if h.latencyEMA.CompareAndSwap(old, newSlow) {
			break
		}
	}
	// Fast EMA α=0.5
	for {
		old := h.latencyFast.Load()
		newFast := (us + old) / 2
		if h.latencyFast.CompareAndSwap(old, newFast) {
			break
		}
	}
}

func (h *AccountHealth) recordWindow(isError bool) {
	now := time.Now()
	cutoff := now.Add(-healthWindowSize)
	h.windowMu.Lock()
	defer h.windowMu.Unlock()

	h.windowTotal = append(h.windowTotal, now)
	if isError {
		h.windowErrors = append(h.windowErrors, now)
	}

	// Prune on write path to cap memory growth
	if len(h.windowTotal) > healthWindowMaxCap {
		h.windowTotal = pruneWindow(h.windowTotal, cutoff)
		h.windowErrors = pruneWindow(h.windowErrors, cutoff)
	}
}

func pruneWindow(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return times
	}
	return times[i:]
}

