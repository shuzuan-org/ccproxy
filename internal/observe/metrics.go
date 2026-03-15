package observe

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// StateProvider supplies runtime state for periodic metrics snapshots.
type StateProvider interface {
	InstanceStates() map[string]InstanceState
}

// InstanceState represents the runtime state of a single instance.
type InstanceState struct {
	Health         string
	Concurrency    int
	MaxConcurrency int
	BudgetState    string
}

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

	instances sync.Map // map[string]*InstanceMetrics
}

// InstanceMetrics holds per-instance atomic counters.
type InstanceMetrics struct {
	RequestsTotal   atomic.Int64
	RequestsSuccess atomic.Int64
	RequestsError   atomic.Int64
	Errors429       atomic.Int64
	Errors529       atomic.Int64
}

// Instance returns the InstanceMetrics for the given instance name,
// creating one lazily if it does not exist. The same pointer is returned
// on every subsequent call for the same name.
func (m *Metrics) Instance(name string) *InstanceMetrics {
	if v, ok := m.instances.Load(name); ok {
		return v.(*InstanceMetrics)
	}
	im := &InstanceMetrics{}
	actual, _ := m.instances.LoadOrStore(name, im)
	return actual.(*InstanceMetrics)
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
// If state is non-nil, per-instance state is also logged. If logger is nil, slog.Default() is used.
// It stops when ctx is cancelled.
func (m *Metrics) StartPeriodicLog(ctx context.Context, interval time.Duration, state StateProvider, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	startTime := time.Now()
	var lastTotal int64
	lastTick := time.Now()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snap := m.Snapshot()
				currentTotal := snap["requests_total"]
				elapsed := time.Since(startTime)
				now := time.Now()
				actualInterval := now.Sub(lastTick)
				rate := float64(currentTotal-lastTotal) / actualInterval.Minutes()
				lastTotal = currentTotal
				lastTick = now

				logger.Info("metrics summary",
					"uptime", elapsed.Round(time.Second).String(),
					"requests_total", snap["requests_total"],
					"requests_per_min", fmt.Sprintf("%.1f", rate),
					"requests_success", snap["requests_success"],
					"requests_error", snap["requests_error"],
					"requests_throttled", snap["requests_throttled"],
					"requests_queued", snap["requests_queued"],
					"retries_total", snap["retries_total"],
					"failovers_total", snap["failovers_total"],
					"instances_429", snap["instances_429"],
					"instances_529", snap["instances_529"],
				)

				if state != nil {
					for name, is := range state.InstanceStates() {
						im := m.Instance(name)
						logger.Info("metrics instance",
							"instance", name,
							"requests", im.RequestsTotal.Load(),
							"success", im.RequestsSuccess.Load(),
							"errors", im.RequestsError.Load(),
							"errors_429", im.Errors429.Load(),
							"errors_529", im.Errors529.Load(),
							"state", is.Health,
							"concurrency", fmt.Sprintf("%d/%d", is.Concurrency, is.MaxConcurrency),
							"budget", is.BudgetState,
						)
					}
				}
			}
		}
	}()
}
