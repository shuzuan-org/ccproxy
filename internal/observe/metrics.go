package observe

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
)

// StateProvider supplies runtime state for periodic metrics snapshots.
type StateProvider interface {
	AccountStates() map[string]AccountState
}

// UpdateStatusProvider supplies update state for periodic logging.
type UpdateStatusProvider interface {
	Status() UpdateStatus
}

// UpdateStatus represents the current update state for logging.
type UpdateStatus struct {
	CurrentVersion string
	LatestVersion  string
	LastCheck      time.Time
}

// AccountState represents the runtime state of a single account.
type AccountState struct {
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
	Accounts429      atomic.Int64
	Accounts529      atomic.Int64

	accounts sync.Map // map[string]*AccountMetrics
}

// AccountMetrics holds per-account atomic counters.
type AccountMetrics struct {
	RequestsTotal   atomic.Int64
	RequestsSuccess atomic.Int64
	RequestsError   atomic.Int64
	Errors429       atomic.Int64
	Errors529       atomic.Int64
}

// Account returns the AccountMetrics for the given account name,
// creating one lazily if it does not exist. The same pointer is returned
// on every subsequent call for the same name.
func (m *Metrics) Account(name string) *AccountMetrics {
	if v, ok := m.accounts.Load(name); ok {
		return v.(*AccountMetrics)
	}
	am := &AccountMetrics{}
	actual, _ := m.accounts.LoadOrStore(name, am)
	return actual.(*AccountMetrics)
}

// Global is the singleton metrics object used throughout the application.
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
		"accounts_429":      m.Accounts429.Load(),
		"accounts_529":      m.Accounts529.Load(),
	}
}

// StartPeriodicLog starts a goroutine that logs a metrics snapshot every interval.
// If state is non-nil, per-account state is also logged. If logger is nil, slog.Default() is used.
// It stops when ctx is cancelled.
func (m *Metrics) StartPeriodicLog(ctx context.Context, interval time.Duration, state StateProvider, updateProv UpdateStatusProvider, logger *slog.Logger) {
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
					"accounts_429", snap["accounts_429"],
					"accounts_529", snap["accounts_529"],
				)

				if state != nil {
					for name, as := range state.AccountStates() {
						am := m.Account(name)
						logger.Info("metrics account",
							"account", name,
							"requests", am.RequestsTotal.Load(),
							"success", am.RequestsSuccess.Load(),
							"errors", am.RequestsError.Load(),
							"errors_429", am.Errors429.Load(),
							"errors_529", am.Errors529.Load(),
							"state", as.Health,
							"concurrency", fmt.Sprintf("%d/%d", as.Concurrency, as.MaxConcurrency),
							"budget", as.BudgetState,
						)
					}
				}

				// System resource metrics
				logSystemMetrics(logger)

				if updateProv != nil {
					us := updateProv.Status()
					attrs := []any{
						"current_version", us.CurrentVersion,
					}
					if us.LatestVersion != "" {
						attrs = append(attrs, "latest_version", us.LatestVersion)
					}
					if !us.LastCheck.IsZero() {
						attrs = append(attrs, "last_check", us.LastCheck.Format(time.RFC3339))
					}
					logger.Info("update status", attrs...)
				}
			}
		}
	}()
}

// logSystemMetrics logs Go runtime and system resource metrics.
func logSystemMetrics(logger *slog.Logger) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	attrs := []any{
		"goroutines", runtime.NumGoroutine(),
		"heap_alloc_mb", fmt.Sprintf("%.1f", float64(memStats.HeapAlloc)/1024/1024),
		"heap_sys_mb", fmt.Sprintf("%.1f", float64(memStats.HeapSys)/1024/1024),
		"gc_cycles", memStats.NumGC,
		"gc_pause_ms", fmt.Sprintf("%.2f", float64(memStats.PauseNs[(memStats.NumGC+255)%256])/1e6),
	}

	// System CPU (non-blocking, interval=0)
	if cpuPercent, err := cpu.Percent(0, false); err == nil && len(cpuPercent) > 0 {
		attrs = append(attrs, "cpu_percent", fmt.Sprintf("%.1f", cpuPercent[0]))
	}

	// System memory
	if vmStat, err := mem.VirtualMemory(); err == nil {
		attrs = append(attrs,
			"mem_total_mb", fmt.Sprintf("%.0f", float64(vmStat.Total)/1024/1024),
			"mem_used_mb", fmt.Sprintf("%.0f", float64(vmStat.Used)/1024/1024),
			"mem_percent", fmt.Sprintf("%.1f", vmStat.UsedPercent),
		)
	}

	// System load average
	if loadAvg, err := load.Avg(); err == nil {
		attrs = append(attrs,
			"load_1", fmt.Sprintf("%.2f", loadAvg.Load1),
			"load_5", fmt.Sprintf("%.2f", loadAvg.Load5),
			"load_15", fmt.Sprintf("%.2f", loadAvg.Load15),
		)
	}

	logger.Info("metrics system", attrs...)
}
