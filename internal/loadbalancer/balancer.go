package loadbalancer

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/google/uuid"
)

var (
	ErrNoHealthyInstances = errors.New("no healthy instances available")
	ErrAllInstancesBusy   = errors.New("all instances at capacity")
)

const sessionTTL = 1 * time.Hour

type SessionInfo struct {
	InstanceName string
	LastRequest  time.Time
}

type SelectResult struct {
	Instance  config.InstanceConfig
	RequestID string
	Release   func()
}

type Balancer struct {
	mu           sync.RWMutex
	instances    []config.InstanceConfig
	tracker      *ConcurrencyTracker
	health       map[string]*AccountHealth // per-instance health tracking
	sessions     sync.Map                  // sessionKey → *SessionInfo
	lastUsed     sync.Map                  // instanceName → time.Time
	throttle     *PoolThrottle
	usageFetcher *UsageFetcher
}

func NewBalancer(instances []config.InstanceConfig, tracker *ConcurrencyTracker) *Balancer {
	enabled := filterEnabled(instances)
	health := make(map[string]*AccountHealth, len(enabled))
	for _, inst := range enabled {
		health[inst.Name] = NewAccountHealth(inst.Name)
	}
	queueCap := len(enabled) * 3
	if queueCap < 10 {
		queueCap = 10
	}
	return &Balancer{
		instances: enabled,
		tracker:   tracker,
		health:    health,
		throttle:  NewPoolThrottle(queueCap),
	}
}

func filterEnabled(instances []config.InstanceConfig) []config.InstanceConfig {
	var result []config.InstanceConfig
	for _, inst := range instances {
		if inst.IsEnabled() {
			result = append(result, inst)
		}
	}
	return result
}

// SetUsageFetcher injects the usage fetcher after construction.
func (b *Balancer) SetUsageFetcher(f *UsageFetcher) {
	b.usageFetcher = f
}

// instanceCandidate holds a candidate instance for selection.
type instanceCandidate struct {
	instance config.InstanceConfig
	loadRate int
	lastUsed time.Time
	score    float64
}

// SelectInstance implements 3-layer selection with pool-level backpressure:
// L1 Pool: SRE throttling + utilization delay + wait queue
// L2 Sticky: Session affinity (1h TTL) with budget-aware concurrency
// L3 Score: Load-aware selection with budget state filtering
func (b *Balancer) SelectInstance(ctx context.Context, sessionKey string, excludeInstances map[string]bool, isStream bool) (*SelectResult, error) {
	// L1: Pool-level backpressure
	b.throttle.RecordRequest()
	if b.throttle.ShouldThrottle() {
		if !b.throttle.Enqueue(ctx, isStream) {
			return nil, ErrAllInstancesBusy
		}
		defer b.throttle.Dequeue()
	}

	// Utilization-based delay
	budgets := b.allBudgets()
	poolUtil := PoolUtilization(budgets)
	if delay := UtilizationDelay(poolUtil); delay > 0 {
		slog.Debug("backpressure: utilization delay", "pool_util", poolUtil, "delay", delay.String())
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}

	b.mu.RLock()
	instances := b.instances
	health := b.health
	b.mu.RUnlock()

	if len(instances) == 0 {
		return nil, ErrNoHealthyInstances
	}

	requestID := uuid.New().String()

	// Layer 2: Sticky session check
	if sessionKey != "" {
		if info, ok := b.sessions.Load(sessionKey); ok {
			si := info.(*SessionInfo)
			if time.Since(si.LastRequest) < sessionTTL {
				inst := b.findInstance(si.InstanceName)
				if inst != nil && !excludeInstances[inst.Name] {
					h := health[inst.Name]
					if h == nil || h.IsAvailable() {
						// Use dynamic concurrency for sticky sessions
						effectiveMax := inst.MaxConcurrency
						if h != nil {
							effectiveMax = EffectiveMaxConcurrency(h.budget, inst.MaxConcurrency)
						}
						rate := b.tracker.LoadRate(inst.Name, effectiveMax)
						if rate < 100 {
							if release, ok := b.tracker.Acquire(inst.Name, requestID, effectiveMax); ok {
								b.sessions.Store(sessionKey, &SessionInfo{
									InstanceName: si.InstanceName,
									LastRequest:  time.Now(),
								})
								return &SelectResult{Instance: *inst, RequestID: requestID, Release: release}, nil
							}
						}
					}
				}
			}
			// Sticky session expired or instance unavailable
			b.sessions.Delete(sessionKey)
		}
	}

	// Layer 3: Score-based selection with budget state filtering
	candidates := make([]instanceCandidate, 0, len(instances))
	for _, inst := range instances {
		if excludeInstances[inst.Name] {
			continue
		}
		h := health[inst.Name]
		if h != nil && !h.IsAvailable() {
			continue
		}

		// Check budget state — skip Blocked and StickyOnly instances
		if h != nil && h.budget != nil {
			state := h.budget.State()
			if state == StateBlocked || state == StateStickyOnly {
				continue
			}
		}

		effectiveMax := inst.MaxConcurrency
		if h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, inst.MaxConcurrency)
		}
		rate := b.tracker.LoadRate(inst.Name, effectiveMax)
		if rate >= 100 {
			continue
		}
		var lu time.Time
		if v, ok := b.lastUsed.Load(inst.Name); ok {
			lu = v.(time.Time)
		}
		score := 0.0
		if h != nil {
			score = h.Score(rate)
		}
		candidates = append(candidates, instanceCandidate{
			instance: inst, loadRate: rate, lastUsed: lu, score: score,
		})
	}

	if len(candidates) == 0 {
		return nil, ErrAllInstancesBusy
	}

	// Short-circuit: single candidate, no sorting needed
	if len(candidates) == 1 {
		c := candidates[0]
		effectiveMax := c.instance.MaxConcurrency
		if h := health[c.instance.Name]; h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, c.instance.MaxConcurrency)
		}
		if release, ok := b.tracker.Acquire(c.instance.Name, requestID, effectiveMax); ok {
			b.lastUsed.Store(c.instance.Name, time.Now())
			return &SelectResult{Instance: c.instance, RequestID: requestID, Release: release}, nil
		}
		return nil, ErrAllInstancesBusy
	}

	// Two candidates: simple comparison instead of sort.Slice
	if len(candidates) == 2 {
		a, z := candidates[0], candidates[1]
		if a.score > z.score || (a.score == z.score && a.lastUsed.After(z.lastUsed)) {
			candidates[0], candidates[1] = z, a
		}
	} else {
		// Sort by Score (lower = better), break ties with LRU
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].score != candidates[j].score {
				return candidates[i].score < candidates[j].score
			}
			return candidates[i].lastUsed.Before(candidates[j].lastUsed)
		})
	}

	// Try to acquire slot
	for _, c := range candidates {
		effectiveMax := c.instance.MaxConcurrency
		if h := health[c.instance.Name]; h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, c.instance.MaxConcurrency)
		}
		if release, ok := b.tracker.Acquire(c.instance.Name, requestID, effectiveMax); ok {
			b.lastUsed.Store(c.instance.Name, time.Now())
			return &SelectResult{Instance: c.instance, RequestID: requestID, Release: release}, nil
		}
	}

	return nil, ErrAllInstancesBusy
}

func (b *Balancer) findInstance(name string) *config.InstanceConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, inst := range b.instances {
		if inst.Name == name {
			found := inst
			return &found
		}
	}
	return nil
}

// BindSession creates or updates a sticky session binding.
func (b *Balancer) BindSession(sessionKey, instanceName string) {
	if sessionKey == "" {
		return
	}
	b.sessions.Store(sessionKey, &SessionInfo{
		InstanceName: instanceName,
		LastRequest:  time.Now(),
	})
}

// ClearSession removes a sticky session binding.
func (b *Balancer) ClearSession(sessionKey string) {
	b.sessions.Delete(sessionKey)
}

// UpdateInstances atomically replaces the instance list (for hot-reload),
// preserving health state for existing instances and cleaning up removed ones.
func (b *Balancer) UpdateInstances(instances []config.InstanceConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.instances = filterEnabled(instances)

	newHealth := make(map[string]*AccountHealth, len(b.instances))
	var added, removed []string
	for _, inst := range b.instances {
		if existing, ok := b.health[inst.Name]; ok {
			newHealth[inst.Name] = existing
		} else {
			newHealth[inst.Name] = NewAccountHealth(inst.Name)
			added = append(added, inst.Name)
		}
	}
	for name := range b.health {
		if _, ok := newHealth[name]; !ok {
			removed = append(removed, name)
		}
	}
	b.health = newHealth

	// Clean up tracker entries for removed instances
	for _, name := range removed {
		b.tracker.RemoveInstance(name)
	}

	if len(added) > 0 || len(removed) > 0 {
		slog.Info("balancer: instances updated",
			"total", len(b.instances),
			"added", added,
			"removed", removed,
		)
	}
}

// StartCleanup starts background goroutines for session and stale slot cleanup.
func (b *Balancer) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.cleanupSessions()
				b.tracker.CleanupStale()
			}
		}
	}()
}

func (b *Balancer) cleanupSessions() {
	b.sessions.Range(func(key, value interface{}) bool {
		si := value.(*SessionInfo)
		if time.Since(si.LastRequest) >= sessionTTL {
			b.sessions.Delete(key)
		}
		return true
	})
}

// ReportResult reports a request outcome to the health tracker for the given instance.
func (b *Balancer) ReportResult(instanceName string, statusCode int, latencyUs int64, retryAfter time.Duration, responseHeaders http.Header) {
	b.mu.RLock()
	h := b.health[instanceName]
	b.mu.RUnlock()
	if h == nil {
		return
	}
	if statusCode >= 200 && statusCode < 400 {
		h.RecordSuccess(latencyUs)
		// Update budget from response headers on success
		if responseHeaders != nil {
			h.budget.UpdateFromHeaders(responseHeaders)
		}
		// Record accept for SRE throttle
		b.throttle.RecordAccept()
		// Trigger usage fetch if budget data is stale
		if b.usageFetcher != nil && !h.budget.HasRecentData(usageStaleThreshold) {
			go b.usageFetcher.FetchIfNeeded(context.Background(), instanceName, h.budget)
		}
	} else {
		h.RecordError(statusCode, retryAfter, responseHeaders)
	}
}

// GetHealth returns the health tracker for a specific instance.
func (b *Balancer) GetHealth(instanceName string) *AccountHealth {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.health[instanceName]
}

// AllHealth returns a snapshot of all health trackers.
func (b *Balancer) AllHealth() map[string]*AccountHealth {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]*AccountHealth, len(b.health))
	for k, v := range b.health {
		result[k] = v
	}
	return result
}

// GetInstances returns current instance list (for admin API).
func (b *Balancer) GetInstances() []config.InstanceConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]config.InstanceConfig, len(b.instances))
	copy(result, b.instances)
	return result
}

// GetTracker returns the concurrency tracker (for admin API).
func (b *Balancer) GetTracker() *ConcurrencyTracker {
	return b.tracker
}

// ActiveSessions returns count of active sessions.
func (b *Balancer) ActiveSessions() int {
	count := 0
	b.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// allBudgets returns a snapshot of all budget controllers.
func (b *Balancer) allBudgets() map[string]*BudgetController {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]*BudgetController, len(b.health))
	for name, h := range b.health {
		result[name] = h.budget
	}
	return result
}
