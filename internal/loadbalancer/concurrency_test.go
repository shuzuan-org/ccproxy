package loadbalancer

import (
	"sync"
	"testing"
	"time"
)

func TestConcurrencyTracker_AcquireSuccess(t *testing.T) {
	tracker := NewConcurrencyTracker()
	release, ok := tracker.Acquire("inst1", "req1", 2)
	if !ok {
		t.Fatal("expected Acquire to succeed")
	}
	if release == nil {
		t.Fatal("expected non-nil release func")
	}
	if tracker.ActiveSlots("inst1") != 1 {
		t.Errorf("expected 1 active slot, got %d", tracker.ActiveSlots("inst1"))
	}
	release()
}

func TestConcurrencyTracker_AcquireAtCapacity(t *testing.T) {
	tracker := NewConcurrencyTracker()
	release1, ok1 := tracker.Acquire("inst1", "req1", 2)
	if !ok1 {
		t.Fatal("first acquire should succeed")
	}
	defer release1()

	release2, ok2 := tracker.Acquire("inst1", "req2", 2)
	if !ok2 {
		t.Fatal("second acquire should succeed")
	}
	defer release2()

	// Third acquire should fail at capacity=2
	_, ok3 := tracker.Acquire("inst1", "req3", 2)
	if ok3 {
		t.Fatal("third acquire should fail (at capacity)")
	}
}

func TestConcurrencyTracker_ReleaseDecreasesActiveSlots(t *testing.T) {
	tracker := NewConcurrencyTracker()
	release, ok := tracker.Acquire("inst1", "req1", 2)
	if !ok {
		t.Fatal("acquire should succeed")
	}

	if tracker.ActiveSlots("inst1") != 1 {
		t.Errorf("expected 1 active slot before release")
	}

	release()

	if tracker.ActiveSlots("inst1") != 0 {
		t.Errorf("expected 0 active slots after release, got %d", tracker.ActiveSlots("inst1"))
	}
}

func TestConcurrencyTracker_LoadRateCalculation(t *testing.T) {
	tracker := NewConcurrencyTracker()

	// 0 active, 0 waiting → 0%
	rate := tracker.LoadRate("inst1", 4)
	if rate != 0 {
		t.Errorf("expected 0%%, got %d%%", rate)
	}

	// Acquire 2 slots with maxConcurrency=4 → 50%
	r1, _ := tracker.Acquire("inst1", "req1", 4)
	defer r1()
	r2, _ := tracker.Acquire("inst1", "req2", 4)
	defer r2()

	rate = tracker.LoadRate("inst1", 4)
	if rate != 50 {
		t.Errorf("expected 50%%, got %d%%", rate)
	}
}

func TestConcurrencyTracker_WaitingAffectsLoadRate(t *testing.T) {
	tracker := NewConcurrencyTracker()

	// 2 active + 2 waiting out of max=4 → 100%
	r1, _ := tracker.Acquire("inst1", "req1", 4)
	defer r1()
	r2, _ := tracker.Acquire("inst1", "req2", 4)
	defer r2()

	tracker.IncrementWaiting("inst1")
	tracker.IncrementWaiting("inst1")

	rate := tracker.LoadRate("inst1", 4)
	if rate != 100 {
		t.Errorf("expected 100%%, got %d%%", rate)
	}

	tracker.DecrementWaiting("inst1")
	rate = tracker.LoadRate("inst1", 4)
	if rate != 75 {
		t.Errorf("expected 75%% after decrement, got %d%%", rate)
	}

	tracker.DecrementWaiting("inst1")
	rate = tracker.LoadRate("inst1", 4)
	if rate != 50 {
		t.Errorf("expected 50%% after second decrement, got %d%%", rate)
	}
}

func TestConcurrencyTracker_CleanupStale(t *testing.T) {
	tracker := NewConcurrencyTracker()

	// Manually insert a stale slot (older than slotTTL)
	tracker.mapMu.Lock()
	tracker.slots["inst1"] = map[string]time.Time{
		"stale-req": time.Now().Add(-(slotTTL + time.Second)),
		"fresh-req": time.Now(),
	}
	tracker.mapMu.Unlock()

	tracker.CleanupStale()

	if tracker.ActiveSlots("inst1") != 1 {
		t.Errorf("expected 1 active slot after cleanup (fresh-req), got %d", tracker.ActiveSlots("inst1"))
	}

	// Verify the stale one is gone and fresh is still there
	tracker.mapMu.Lock()
	_, staleExists := tracker.slots["inst1"]["stale-req"]
	_, freshExists := tracker.slots["inst1"]["fresh-req"]
	tracker.mapMu.Unlock()

	if staleExists {
		t.Error("stale-req should have been cleaned up")
	}
	if !freshExists {
		t.Error("fresh-req should still be present")
	}
}

func TestConcurrencyTracker_IdempotentAcquire(t *testing.T) {
	tracker := NewConcurrencyTracker()

	r1, ok1 := tracker.Acquire("inst1", "req1", 2)
	if !ok1 {
		t.Fatal("first acquire should succeed")
	}
	defer r1()

	// Same requestID → idempotent, should succeed again
	r2, ok2 := tracker.Acquire("inst1", "req1", 2)
	if !ok2 {
		t.Fatal("idempotent acquire should succeed")
	}
	defer r2()

	// Still only 1 active slot (not doubled)
	if tracker.ActiveSlots("inst1") != 1 {
		t.Errorf("expected 1 active slot (idempotent), got %d", tracker.ActiveSlots("inst1"))
	}
}

func TestConcurrencyTracker_ConcurrentAcquire(t *testing.T) {
	tracker := NewConcurrencyTracker()
	maxConcurrency := 5
	goroutines := 20
	successCount := 0
	var mu sync.Mutex
	var wg sync.WaitGroup

	releases := make([]func(), 0, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			reqID := time.Now().String() + string(rune('a'+id))
			release, ok := tracker.Acquire("inst1", reqID, maxConcurrency)
			mu.Lock()
			if ok {
				successCount++
				releases = append(releases, release)
			}
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// At most maxConcurrency slots should be acquired
	if successCount > maxConcurrency {
		t.Errorf("expected at most %d successful acquires, got %d", maxConcurrency, successCount)
	}

	// Active slots must match success count
	active := tracker.ActiveSlots("inst1")
	if active != successCount {
		t.Errorf("expected %d active slots, got %d", successCount, active)
	}

	// Release all
	for _, rel := range releases {
		rel()
	}

	if tracker.ActiveSlots("inst1") != 0 {
		t.Errorf("expected 0 active slots after all releases")
	}
}

func TestConcurrencyTracker_RemoveAccount(t *testing.T) {
	tracker := NewConcurrencyTracker()

	// Acquire some slots
	r1, ok := tracker.Acquire("inst1", "req1", 5)
	if !ok {
		t.Fatal("acquire should succeed")
	}
	_ = r1 // intentionally not releasing

	r2, ok := tracker.Acquire("inst1", "req2", 5)
	if !ok {
		t.Fatal("acquire should succeed")
	}
	_ = r2

	tracker.IncrementWaiting("inst1")

	if tracker.ActiveSlots("inst1") != 2 {
		t.Fatalf("expected 2 active slots, got %d", tracker.ActiveSlots("inst1"))
	}

	// Remove account
	tracker.RemoveAccount("inst1")

	if tracker.ActiveSlots("inst1") != 0 {
		t.Errorf("expected 0 active slots after RemoveAccount, got %d", tracker.ActiveSlots("inst1"))
	}

	// LoadRate should also be 0
	if rate := tracker.LoadRate("inst1", 5); rate != 0 {
		t.Errorf("expected 0%% load rate after RemoveAccount, got %d%%", rate)
	}
}
