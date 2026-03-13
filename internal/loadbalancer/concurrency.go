package loadbalancer

import (
	"log/slog"
	"sync"
	"time"
)

const slotTTL = 15 * time.Minute

// ConcurrencyTracker tracks per-instance concurrency slots in memory.
// Uses per-instance locking to avoid serializing all instances behind a single mutex.
type ConcurrencyTracker struct {
	mapMu   sync.RWMutex                     // protects slots and instanceMu maps
	slots   map[string]map[string]time.Time   // instanceName → {requestID → acquireTime}
	instMu  map[string]*sync.Mutex            // instanceName → per-instance lock
	waiting map[string]int32                  // instanceName → waiting count
}

func NewConcurrencyTracker() *ConcurrencyTracker {
	return &ConcurrencyTracker{
		slots:   make(map[string]map[string]time.Time),
		instMu:  make(map[string]*sync.Mutex),
		waiting: make(map[string]int32),
	}
}

// getInstMu returns the per-instance mutex, creating it if needed.
func (t *ConcurrencyTracker) getInstMu(instanceName string) *sync.Mutex {
	t.mapMu.RLock()
	mu, ok := t.instMu[instanceName]
	t.mapMu.RUnlock()
	if ok {
		return mu
	}
	t.mapMu.Lock()
	// Double-check after acquiring write lock
	if mu, ok = t.instMu[instanceName]; ok {
		t.mapMu.Unlock()
		return mu
	}
	mu = &sync.Mutex{}
	t.instMu[instanceName] = mu
	t.mapMu.Unlock()
	return mu
}

// TryAcquire atomically checks capacity and acquires a slot in one lock operation.
// Returns release func, success bool, and current load rate.
func (t *ConcurrencyTracker) TryAcquire(instanceName, requestID string, maxConcurrency int) (release func(), ok bool, loadRate int) {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	mu := t.getInstMu(instanceName)
	mu.Lock()

	t.mapMu.RLock()
	slots := t.slots[instanceName]
	waiting := int(t.waiting[instanceName])
	t.mapMu.RUnlock()

	if slots == nil {
		t.mapMu.Lock()
		slots = make(map[string]time.Time)
		t.slots[instanceName] = slots
		t.mapMu.Unlock()
	}

	active := len(slots)
	rate := (active + waiting) * 100 / maxConcurrency

	// Check if already acquired (idempotent)
	if _, exists := slots[requestID]; exists {
		slots[requestID] = time.Now()
		mu.Unlock()
		return func() { t.release(instanceName, requestID) }, true, rate
	}

	if active >= maxConcurrency {
		mu.Unlock()
		return nil, false, rate
	}

	slots[requestID] = time.Now()
	mu.Unlock()
	return func() { t.release(instanceName, requestID) }, true, rate
}

// Acquire tries to acquire a concurrency slot for the given instance.
// Returns a release function and true if successful, nil and false if at capacity.
func (t *ConcurrencyTracker) Acquire(instanceName, requestID string, maxConcurrency int) (release func(), ok bool) {
	rel, acquired, _ := t.TryAcquire(instanceName, requestID, maxConcurrency)
	return rel, acquired
}

func (t *ConcurrencyTracker) release(instanceName, requestID string) {
	mu := t.getInstMu(instanceName)
	mu.Lock()
	t.mapMu.RLock()
	if t.slots[instanceName] != nil {
		delete(t.slots[instanceName], requestID)
	}
	t.mapMu.RUnlock()
	mu.Unlock()
}

// LoadRate returns the load percentage: (active + waiting) * 100 / maxConcurrency
func (t *ConcurrencyTracker) LoadRate(instanceName string, maxConcurrency int) int {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	mu := t.getInstMu(instanceName)
	mu.Lock()
	t.mapMu.RLock()
	active := len(t.slots[instanceName])
	waiting := int(t.waiting[instanceName])
	t.mapMu.RUnlock()
	mu.Unlock()
	return (active + waiting) * 100 / maxConcurrency
}

// LoadInfo returns detailed load information.
func (t *ConcurrencyTracker) LoadInfo(instanceName string, maxConcurrency int) (active int, waiting int, rate int) {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	mu := t.getInstMu(instanceName)
	mu.Lock()
	t.mapMu.RLock()
	active = len(t.slots[instanceName])
	waiting = int(t.waiting[instanceName])
	t.mapMu.RUnlock()
	mu.Unlock()
	rate = (active + waiting) * 100 / maxConcurrency
	return
}

// IncrementWaiting increments the waiting count for an instance.
func (t *ConcurrencyTracker) IncrementWaiting(instanceName string) {
	mu := t.getInstMu(instanceName)
	mu.Lock()
	t.mapMu.Lock()
	t.waiting[instanceName]++
	t.mapMu.Unlock()
	mu.Unlock()
}

// DecrementWaiting decrements the waiting count for an instance.
func (t *ConcurrencyTracker) DecrementWaiting(instanceName string) {
	mu := t.getInstMu(instanceName)
	mu.Lock()
	t.mapMu.Lock()
	if t.waiting[instanceName] > 0 {
		t.waiting[instanceName]--
	}
	t.mapMu.Unlock()
	mu.Unlock()
}

// CleanupStale removes slots that are older than the given TTL.
// Uses per-instance locks to avoid holding a global lock during the entire scan.
func (t *ConcurrencyTracker) CleanupStale() {
	// Get snapshot of instance names
	t.mapMu.RLock()
	names := make([]string, 0, len(t.slots))
	for name := range t.slots {
		names = append(names, name)
	}
	t.mapMu.RUnlock()

	cutoff := time.Now().Add(-slotTTL)
	staleCount := 0
	for _, instance := range names {
		mu := t.getInstMu(instance)
		mu.Lock()
		t.mapMu.RLock()
		slots := t.slots[instance]
		t.mapMu.RUnlock()
		if slots == nil {
			mu.Unlock()
			continue
		}
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
			t.mapMu.Lock()
			delete(t.slots, instance)
			t.mapMu.Unlock()
		}
		mu.Unlock()
	}
	if staleCount > 0 {
		slog.Info("concurrency: stale slots cleaned", "count", staleCount)
	}
}

// ActiveSlots returns the number of active slots for an instance.
func (t *ConcurrencyTracker) ActiveSlots(instanceName string) int {
	mu := t.getInstMu(instanceName)
	mu.Lock()
	t.mapMu.RLock()
	count := len(t.slots[instanceName])
	t.mapMu.RUnlock()
	mu.Unlock()
	return count
}

// RemoveInstance removes all tracking data for a removed instance.
func (t *ConcurrencyTracker) RemoveInstance(instanceName string) {
	t.mapMu.Lock()
	delete(t.slots, instanceName)
	delete(t.waiting, instanceName)
	delete(t.instMu, instanceName)
	t.mapMu.Unlock()
}
