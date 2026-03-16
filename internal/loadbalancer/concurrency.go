package loadbalancer

import (
	"log/slog"
	"sync"
	"time"
)

const slotTTL = 15 * time.Minute

// ConcurrencyTracker tracks per-account concurrency slots in memory.
// Uses per-account locking to avoid serializing all accounts behind a single mutex.
type ConcurrencyTracker struct {
	mapMu   sync.RWMutex                     // protects slots and acctMu maps
	slots   map[string]map[string]time.Time   // accountName → {requestID → acquireTime}
	acctMu  map[string]*sync.Mutex            // accountName → per-account lock
	waiting map[string]int32                  // accountName → waiting count
}

func NewConcurrencyTracker() *ConcurrencyTracker {
	return &ConcurrencyTracker{
		slots:   make(map[string]map[string]time.Time),
		acctMu:  make(map[string]*sync.Mutex),
		waiting: make(map[string]int32),
	}
}

// getAcctMu returns the per-account mutex, creating it if needed.
func (t *ConcurrencyTracker) getAcctMu(accountName string) *sync.Mutex {
	t.mapMu.RLock()
	mu, ok := t.acctMu[accountName]
	t.mapMu.RUnlock()
	if ok {
		return mu
	}
	t.mapMu.Lock()
	// Double-check after acquiring write lock
	if mu, ok = t.acctMu[accountName]; ok {
		t.mapMu.Unlock()
		return mu
	}
	mu = &sync.Mutex{}
	t.acctMu[accountName] = mu
	t.mapMu.Unlock()
	return mu
}

// TryAcquire atomically checks capacity and acquires a slot in one lock operation.
// Returns release func, success bool, and current load rate.
func (t *ConcurrencyTracker) TryAcquire(accountName, requestID string, maxConcurrency int) (release func(), ok bool, loadRate int) {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	mu := t.getAcctMu(accountName)
	mu.Lock()

	t.mapMu.RLock()
	slots := t.slots[accountName]
	waiting := int(t.waiting[accountName])
	t.mapMu.RUnlock()

	if slots == nil {
		t.mapMu.Lock()
		// Double-check after acquiring write lock to avoid overwriting
		// a map that another goroutine just created.
		if existing := t.slots[accountName]; existing != nil {
			slots = existing
		} else {
			slots = make(map[string]time.Time)
			t.slots[accountName] = slots
		}
		t.mapMu.Unlock()
	}

	active := len(slots)
	rate := (active + waiting) * 100 / maxConcurrency

	// Check if already acquired (idempotent)
	if _, exists := slots[requestID]; exists {
		slots[requestID] = time.Now()
		mu.Unlock()
		return func() { t.release(accountName, requestID) }, true, rate
	}

	if active >= maxConcurrency {
		mu.Unlock()
		slog.Debug("concurrency: acquire rejected",
			"account", accountName,
			"active", active,
			"max_concurrency", maxConcurrency,
		)
		return nil, false, rate
	}

	slots[requestID] = time.Now()
	mu.Unlock()
	return func() { t.release(accountName, requestID) }, true, rate
}

// Acquire tries to acquire a concurrency slot for the given account.
// Returns a release function and true if successful, nil and false if at capacity.
func (t *ConcurrencyTracker) Acquire(accountName, requestID string, maxConcurrency int) (release func(), ok bool) {
	rel, acquired, _ := t.TryAcquire(accountName, requestID, maxConcurrency)
	return rel, acquired
}

func (t *ConcurrencyTracker) release(accountName, requestID string) {
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.RLock()
	if t.slots[accountName] != nil {
		delete(t.slots[accountName], requestID)
	}
	t.mapMu.RUnlock()
	mu.Unlock()
}

// LoadRate returns the load percentage: (active + waiting) * 100 / maxConcurrency
func (t *ConcurrencyTracker) LoadRate(accountName string, maxConcurrency int) int {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.RLock()
	active := len(t.slots[accountName])
	waiting := int(t.waiting[accountName])
	t.mapMu.RUnlock()
	mu.Unlock()
	return (active + waiting) * 100 / maxConcurrency
}

// LoadInfo returns detailed load information.
func (t *ConcurrencyTracker) LoadInfo(accountName string, maxConcurrency int) (active int, waiting int, rate int) {
	if maxConcurrency <= 0 {
		maxConcurrency = 1
	}
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.RLock()
	active = len(t.slots[accountName])
	waiting = int(t.waiting[accountName])
	t.mapMu.RUnlock()
	mu.Unlock()
	rate = (active + waiting) * 100 / maxConcurrency
	return
}

// IncrementWaiting increments the waiting count for an account.
func (t *ConcurrencyTracker) IncrementWaiting(accountName string) {
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.Lock()
	t.waiting[accountName]++
	t.mapMu.Unlock()
	mu.Unlock()
}

// DecrementWaiting decrements the waiting count for an account.
func (t *ConcurrencyTracker) DecrementWaiting(accountName string) {
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.Lock()
	if t.waiting[accountName] > 0 {
		t.waiting[accountName]--
	}
	t.mapMu.Unlock()
	mu.Unlock()
}

// CleanupStale removes slots that are older than the given TTL.
// Uses per-account locks to avoid holding a global lock during the entire scan.
func (t *ConcurrencyTracker) CleanupStale() {
	// Get snapshot of account names
	t.mapMu.RLock()
	names := make([]string, 0, len(t.slots))
	for name := range t.slots {
		names = append(names, name)
	}
	t.mapMu.RUnlock()

	cutoff := time.Now().Add(-slotTTL)
	staleCount := 0
	for _, account := range names {
		mu := t.getAcctMu(account)
		mu.Lock()
		t.mapMu.RLock()
		slots := t.slots[account]
		t.mapMu.RUnlock()
		if slots == nil {
			mu.Unlock()
			continue
		}
		for reqID, acquireTime := range slots {
			if acquireTime.Before(cutoff) {
				slog.Warn("concurrency: cleaning stale slot",
					"account", account,
					"request_id", reqID,
					"age", time.Since(acquireTime).String(),
				)
				delete(slots, reqID)
				staleCount++
			}
		}
		if len(slots) == 0 {
			t.mapMu.Lock()
			delete(t.slots, account)
			t.mapMu.Unlock()
		}
		mu.Unlock()
	}
	if staleCount > 0 {
		slog.Info("concurrency: stale slots cleaned", "count", staleCount)
	}
}

// ActiveSlots returns the number of active slots for an account.
func (t *ConcurrencyTracker) ActiveSlots(accountName string) int {
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.RLock()
	count := len(t.slots[accountName])
	t.mapMu.RUnlock()
	mu.Unlock()
	return count
}

// RemoveAccount removes all tracking data for a removed account.
// The per-account mutex is NOT deleted to prevent races where a goroutine
// already holds a reference to the old mutex pointer.
func (t *ConcurrencyTracker) RemoveAccount(accountName string) {
	mu := t.getAcctMu(accountName)
	mu.Lock()
	t.mapMu.Lock()
	delete(t.slots, accountName)
	delete(t.waiting, accountName)
	// Do NOT delete acctMu — released mutex may still be referenced by in-flight goroutines
	t.mapMu.Unlock()
	mu.Unlock()
}
