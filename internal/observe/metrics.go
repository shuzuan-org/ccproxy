package observe

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"
)

// Metrics holds global atomic counters for request-level observability.
type Metrics struct {
	RequestsTotal     atomic.Int64
	RequestsThrottled atomic.Int64
	RequestsQueued    atomic.Int64
	RequestsSuccess   atomic.Int64
	RequestsError     atomic.Int64
	RetriesTotal      atomic.Int64
	FailoversTotal    atomic.Int64
	Instances429      atomic.Int64
	Instances529      atomic.Int64
}

// Global is the singleton metrics instance used throughout the application.
var Global = &Metrics{}

// Snapshot returns a point-in-time copy of all counters.
func (m *Metrics) Snapshot() map[string]int64 {
	return map[string]int64{
		"requests_total":     m.RequestsTotal.Load(),
		"requests_throttled": m.RequestsThrottled.Load(),
		"requests_queued":    m.RequestsQueued.Load(),
		"requests_success":   m.RequestsSuccess.Load(),
		"requests_error":     m.RequestsError.Load(),
		"retries_total":      m.RetriesTotal.Load(),
		"failovers_total":    m.FailoversTotal.Load(),
		"instances_429":      m.Instances429.Load(),
		"instances_529":      m.Instances529.Load(),
	}
}

// StartPeriodicLog starts a goroutine that logs a metrics snapshot every interval.
// It stops when ctx is cancelled.
func (m *Metrics) StartPeriodicLog(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := m.Snapshot()
				slog.Info("metrics summary",
					"requests_total", snap["requests_total"],
					"requests_throttled", snap["requests_throttled"],
					"requests_queued", snap["requests_queued"],
					"requests_success", snap["requests_success"],
					"requests_error", snap["requests_error"],
					"retries_total", snap["retries_total"],
					"failovers_total", snap["failovers_total"],
					"instances_429", snap["instances_429"],
					"instances_529", snap["instances_529"],
				)
			}
		}
	}()
}
