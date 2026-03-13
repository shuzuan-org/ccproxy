package loadbalancer

import (
	"log/slog"
	"sync"
	"time"
)

const slotTTL = 15 * time.Minute

// ConcurrencyTracker tracks per-instance concurrency slots in memory.
type ConcurrencyTracker struct {
	mu      sync.Mutex
	slots   map[string]map[string]time.Time // instanceName → {requestID → acquireTime}
	waiting map[string]int32                // instanceName → waiting count
}

func NewConcurrencyTracker() *ConcurrencyTracker {
	return &ConcurrencyTracker{
		slots:   make(map[string]map[string]time.Time),
		waiting: make(map[string]int32),
	}
}

// Acquire tries to acquire a concurrency slot for the given instance.
// Returns a release function and true if successful, nil and false if at capacity.
func (t *ConcurrencyTracker) Acquire(instanceName, requestID string, maxConcurrency int) (release func(), ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.slots[instanceName] == nil {
		t.slots[instanceName] = make(map[string]time.Time)
	}

	// Check if already acquired (idempotent)
	if _, exists := t.slots[instanceName][requestID]; exists {
		t.slots[instanceName][requestID] = time.Now()
		return func() { t.release(instanceName, requestID) }, true
	}

	if len(t.slots[instanceName]) >= maxConcurrency {
		return nil, false
	}

	t.slots[instanceName][requestID] = time.Now()
	return func() { t.release(instanceName, requestID) }, true
}

func (t *ConcurrencyTracker) release(instanceName, requestID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.slots[instanceName] != nil {
		delete(t.slots[instanceName], requestID)
	}
}

// LoadRate returns the load percentage: (active + waiting) * 100 / maxConcurrency
func (t *ConcurrencyTracker) LoadRate(instanceName string, maxConcurrency int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	active := len(t.slots[instanceName])
	waiting := int(t.waiting[instanceName])
	return (active + waiting) * 100 / maxConcurrency
}

// LoadInfo returns detailed load information.
func (t *ConcurrencyTracker) LoadInfo(instanceName string, maxConcurrency int) (active int, waiting int, rate int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	active = len(t.slots[instanceName])
	waiting = int(t.waiting[instanceName])
	rate = (active + waiting) * 100 / maxConcurrency
	return
}

// IncrementWaiting increments the waiting count for an instance.
func (t *ConcurrencyTracker) IncrementWaiting(instanceName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.waiting[instanceName]++
}

// DecrementWaiting decrements the waiting count for an instance.
func (t *ConcurrencyTracker) DecrementWaiting(instanceName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.waiting[instanceName] > 0 {
		t.waiting[instanceName]--
	}
}

// CleanupStale removes slots that are older than the given TTL.
func (t *ConcurrencyTracker) CleanupStale() {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-slotTTL)
	staleCount := 0
	for instance, slots := range t.slots {
		for reqID, acquireTime := range slots {
			if acquireTime.Before(cutoff) {
				slog.Warn("concurrency: cleaning stale slot",
					"instance", instance,
					"request_id", reqID,
					"age", time.Since(acquireTime).String(),
				)
				delete(slots, reqID)
				staleCount++
			}
		}
		if len(slots) == 0 {
			delete(t.slots, instance)
		}
	}
	if staleCount > 0 {
		slog.Info("concurrency: stale slots cleaned", "count", staleCount)
	}
}

// ActiveSlots returns the number of active slots for an instance.
func (t *ConcurrencyTracker) ActiveSlots(instanceName string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.slots[instanceName])
}

// RemoveInstance removes all tracking data for a removed instance.
func (t *ConcurrencyTracker) RemoveInstance(instanceName string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.slots, instanceName)
	delete(t.waiting, instanceName)
}
