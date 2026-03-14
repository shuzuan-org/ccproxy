package loadbalancer

import (
	"context"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"
)

// PoolThrottle implements SRE-style adaptive throttling with a wait queue
// at the pool level to provide backpressure across all instances.
type PoolThrottle struct {
	mu       sync.Mutex
	requests []time.Time // 2-min sliding window of all requests
	accepts  []time.Time // 2-min sliding window of accepted requests
	K        float64     // multiplier (default 2.0)

	queue chan struct{} // buffered channel for wait queue
}

const (
	throttleWindowSize = 2 * time.Minute
	defaultThrottleK   = 2.0
	maxQueueTimeoutDefault = 30 * time.Second
	maxQueueTimeoutStream  = 10 * time.Second
)

// NewPoolThrottle creates a pool-level throttle with the given queue capacity.
func NewPoolThrottle(queueCap int) *PoolThrottle {
	if queueCap < 10 {
		queueCap = 10
	}
	return &PoolThrottle{
		K:     defaultThrottleK,
		queue: make(chan struct{}, queueCap),
	}
}

// RecordRequest records an incoming request to the sliding window.
func (pt *PoolThrottle) RecordRequest() {
	now := time.Now()
	pt.mu.Lock()
	pt.requests = append(pt.requests, now)
	pt.mu.Unlock()
}

// RecordAccept records a successfully accepted request.
func (pt *PoolThrottle) RecordAccept() {
	now := time.Now()
	pt.mu.Lock()
	pt.accepts = append(pt.accepts, now)
	pt.mu.Unlock()
}

// ShouldThrottle returns true probabilistically based on SRE formula:
// P(reject) = max(0, (requests - K*accepts) / (requests + 1))
func (pt *PoolThrottle) ShouldThrottle() bool {
	pt.mu.Lock()
	cutoff := time.Now().Add(-throttleWindowSize)
	pt.requests = pruneTimeSlice(pt.requests, cutoff)
	pt.accepts = pruneTimeSlice(pt.accepts, cutoff)
	reqs := float64(len(pt.requests))
	accs := float64(len(pt.accepts))
	pt.mu.Unlock()

	if reqs == 0 {
		return false
	}

	prob := math.Max(0, (reqs-pt.K*accs)/(reqs+1))
	if prob <= 0 {
		return false
	}
	throttled := rand.Float64() < prob
	if throttled {
		slog.Debug("throttle: request throttled",
			"probability", prob,
			"requests", int(reqs),
			"accepts", int(accs),
		)
	}
	return throttled
}

// Enqueue attempts to acquire a queue slot with context-aware timeout.
// Returns true if slot acquired, false if timeout or context cancelled.
func (pt *PoolThrottle) Enqueue(ctx context.Context, isStream bool) bool {
	timeout := maxQueueTimeoutDefault
	if isStream {
		timeout = maxQueueTimeoutStream
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case pt.queue <- struct{}{}:
		return true
	case <-timer.C:
		slog.Warn("throttle: queue timeout", "is_stream", isStream)
		return false
	case <-ctx.Done():
		return false
	}
}

// QueueDepth returns the current number of queued requests.
func (pt *PoolThrottle) QueueDepth() int {
	return len(pt.queue)
}

// Dequeue releases a queue slot.
func (pt *PoolThrottle) Dequeue() {
	select {
	case <-pt.queue:
	default:
	}
}

// PoolUtilization computes average MaxUtilization across all budgets.
func PoolUtilization(budgets map[string]*BudgetController) float64 {
	if len(budgets) == 0 {
		return 0
	}
	var sum float64
	for _, b := range budgets {
		sum += b.MaxUtilization()
	}
	return sum / float64(len(budgets))
}

// UtilizationDelay computes the delay to inject based on pool utilization.
// Below 0.5: no delay. Above 0.5: quadratic ramp up to 5s with ±15% jitter.
func UtilizationDelay(poolUtil float64) time.Duration {
	if poolUtil < 0.5 {
		return 0
	}
	// Quadratic: ((poolUtil - 0.5) / 0.5)^2 * 5s
	normalized := (poolUtil - 0.5) / 0.5
	baseDelay := normalized * normalized * 5.0 // seconds

	// Add ±15% jitter
	jitter := 1.0 + (rand.Float64()*0.3 - 0.15)
	delayMs := baseDelay * jitter * 1000.0

	return time.Duration(delayMs) * time.Millisecond
}

func pruneTimeSlice(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(times) && times[i].Before(cutoff) {
		i++
	}
	if i == 0 {
		return times
	}
	return times[i:]
}
