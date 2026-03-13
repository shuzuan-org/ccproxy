package loadbalancer

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

const (
	aimdIncreaseEvery  = 10               // successes before +1
	aimdBeta           = 0.5              // multiplicative decrease factor
	aimdDefaultMin     = int32(1)         // floor
	aimdDefaultMax     = int32(10)        // ceiling
	healthWindowSize   = 5 * time.Minute  // sliding window for error rate
	healthWindowMaxCap = 1000             // max entries per window slice
	cooldown429        = 30 * time.Second // default cooldown for 429
	cooldown529        = 30 * time.Second // default cooldown for 529
	cooldown401        = 60 * time.Second // wait for token refresh
)

// AccountHealth tracks dynamic health state for one instance.
type AccountHealth struct {
	Name string

	// AIMD adaptive concurrency
	maxConcurrency atomic.Int32 // current AIMD limit
	successCount   atomic.Int32 // consecutive successes toward increase
	aimdMin        int32        // floor
	aimdMax        int32        // ceiling

	// Cooldown
	mu             sync.RWMutex
	cooldownUntil  time.Time
	cooldownReason string
	disabled       bool
	disabledReason string

	// Latency EMA (microseconds, lock-free CAS)
	latencyEMA  atomic.Int64 // slow α=0.1
	latencyFast atomic.Int64 // fast α=0.5

	// Sliding window
	windowMu     sync.Mutex
	windowErrors []time.Time
	windowTotal  []time.Time
}

// NewAccountHealth creates a new health tracker for an instance.
func NewAccountHealth(name string, initialMax, ceilingMax int32) *AccountHealth {
	if initialMax < 1 {
		initialMax = aimdDefaultMin
	}
	if ceilingMax < initialMax {
		ceilingMax = initialMax
	}
	h := &AccountHealth{
		Name:    name,
		aimdMin: aimdDefaultMin,
		aimdMax: ceilingMax,
	}
	h.maxConcurrency.Store(initialMax)
	return h
}

// MaxConcurrency returns the current AIMD concurrency limit.
func (h *AccountHealth) MaxConcurrency() int {
	return int(h.maxConcurrency.Load())
}

// RecordSuccess updates health after a successful request.
func (h *AccountHealth) RecordSuccess(latencyUs int64) {
	h.updateLatency(latencyUs)
	h.recordWindow(false)

	count := h.successCount.Add(1)
	if count >= int32(aimdIncreaseEvery) {
		// Additive increase: +1 up to ceiling
		cur := h.maxConcurrency.Load()
		if cur < h.aimdMax {
			h.maxConcurrency.CompareAndSwap(cur, cur+1)
		}
		h.successCount.Store(0)
	}
}

// RecordError updates health after a failed request.
func (h *AccountHealth) RecordError(statusCode int, retryAfter time.Duration) {
	h.recordWindow(true)
	h.successCount.Store(0)

	// AIMD multiplicative decrease
	cur := h.maxConcurrency.Load()
	newMax := int32(float64(cur) * aimdBeta)
	if newMax < h.aimdMin {
		newMax = h.aimdMin
	}
	h.maxConcurrency.Store(newMax)

	switch statusCode {
	case 429:
		cd := retryAfter
		if cd <= 0 {
			cd = cooldown429
		}
		slog.Warn("instance rate limited", "instance", h.Name, "cooldown", cd.String())
		h.SetCooldown(cd, "rate_limited")
	case 529:
		slog.Warn("instance overloaded", "instance", h.Name, "cooldown", cooldown529.String())
		h.SetCooldown(cooldown529, "overloaded")
	case 401:
		slog.Warn("instance auth error, cooling down", "instance", h.Name, "cooldown", cooldown401.String())
		h.SetCooldown(cooldown401, "auth_refresh")
	case 403:
		slog.Error("instance forbidden, disabling", "instance", h.Name)
		h.Disable("forbidden")
	}
}

// IsAvailable returns true if the instance is not disabled and not in cooldown.
func (h *AccountHealth) IsAvailable() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.disabled {
		return false
	}
	return time.Now().After(h.cooldownUntil) || h.cooldownUntil.IsZero()
}

// Score computes a composite score (lower is better).
// score = errorRate*0.4 + normalizedLatency*0.3 + loadRate/100*0.3
func (h *AccountHealth) Score(loadRate int) float64 {
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

	return errRate*0.4 + normalizedLatency*0.3 + float64(loadRate)/100.0*0.3
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

// Disable permanently disables this instance.
func (h *AccountHealth) Disable(reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.disabled = true
	h.disabledReason = reason
}

// IsDisabled returns whether the instance is permanently disabled.
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
