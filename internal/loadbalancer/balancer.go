package loadbalancer

import (
	"context"
	"errors"
	"math/rand"
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
	mu        sync.RWMutex
	instances []config.InstanceConfig
	tracker   *ConcurrencyTracker
	sessions  sync.Map // sessionKey → *SessionInfo
	lastUsed  sync.Map // instanceName → time.Time
}

func NewBalancer(instances []config.InstanceConfig, tracker *ConcurrencyTracker) *Balancer {
	return &Balancer{
		instances: filterEnabled(instances),
		tracker:   tracker,
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

// instanceCandidate holds a candidate instance for selection.
type instanceCandidate struct {
	instance config.InstanceConfig
	loadRate int
	lastUsed time.Time
}

// SelectInstance implements 3-layer selection:
// Layer 1: Sticky session (1h TTL)
// Layer 2: Load-aware selection (Priority → LoadRate → LastUsedAt)
// Layer 3: Fallback (wait or error)
func (b *Balancer) SelectInstance(sessionKey string, excludeInstances map[string]bool) (*SelectResult, error) {
	b.mu.RLock()
	instances := b.instances
	b.mu.RUnlock()

	if len(instances) == 0 {
		return nil, ErrNoHealthyInstances
	}

	requestID := uuid.New().String()

	// Layer 1: Sticky session check
	if sessionKey != "" {
		if info, ok := b.sessions.Load(sessionKey); ok {
			si := info.(*SessionInfo)
			if time.Since(si.LastRequest) < sessionTTL {
				inst := b.findInstance(si.InstanceName)
				if inst != nil && !excludeInstances[inst.Name] {
					rate := b.tracker.LoadRate(inst.Name, inst.MaxConcurrency)
					if rate < 100 {
						if release, ok := b.tracker.Acquire(inst.Name, requestID, inst.MaxConcurrency); ok {
							si.LastRequest = time.Now()
							return &SelectResult{Instance: *inst, RequestID: requestID, Release: release}, nil
						}
					}
				}
			}
			// Sticky session expired or instance unavailable
			b.sessions.Delete(sessionKey)
		}
	}

	// Layer 2: Load-aware selection
	var candidates []instanceCandidate
	for _, inst := range instances {
		if excludeInstances[inst.Name] {
			continue
		}
		rate := b.tracker.LoadRate(inst.Name, inst.MaxConcurrency)
		if rate >= 100 {
			continue
		}
		var lu time.Time
		if v, ok := b.lastUsed.Load(inst.Name); ok {
			lu = v.(time.Time)
		}
		candidates = append(candidates, instanceCandidate{instance: inst, loadRate: rate, lastUsed: lu})
	}

	if len(candidates) == 0 {
		return nil, ErrAllInstancesBusy
	}

	// Sort by Priority → LoadRate → LastUsedAt (LRU)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].instance.Priority != candidates[j].instance.Priority {
			return candidates[i].instance.Priority < candidates[j].instance.Priority
		}
		if candidates[i].loadRate != candidates[j].loadRate {
			return candidates[i].loadRate < candidates[j].loadRate
		}
		return candidates[i].lastUsed.Before(candidates[j].lastUsed)
	})

	// Shuffle within same tier (priority + load rate)
	shuffleTiers(candidates)

	// Try to acquire slot
	for _, c := range candidates {
		if release, ok := b.tracker.Acquire(c.instance.Name, requestID, c.instance.MaxConcurrency); ok {
			b.lastUsed.Store(c.instance.Name, time.Now())
			return &SelectResult{Instance: c.instance, RequestID: requestID, Release: release}, nil
		}
	}

	return nil, ErrAllInstancesBusy
}

// shuffleTiers shuffles candidates within groups that have the same priority and load rate.
func shuffleTiers(candidates []instanceCandidate) {
	i := 0
	for i < len(candidates) {
		j := i + 1
		for j < len(candidates) &&
			candidates[j].instance.Priority == candidates[i].instance.Priority &&
			candidates[j].loadRate == candidates[i].loadRate {
			j++
		}
		if j-i > 1 {
			rand.Shuffle(j-i, func(a, b int) {
				candidates[i+a], candidates[i+b] = candidates[i+b], candidates[i+a]
			})
		}
		i = j
	}
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

// UpdateInstances atomically replaces the instance list (for hot-reload).
func (b *Balancer) UpdateInstances(instances []config.InstanceConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.instances = filterEnabled(instances)
}

// StartCleanup starts background goroutines for session and stale slot cleanup.
func (b *Balancer) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
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
