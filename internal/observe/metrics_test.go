package observe

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMetrics_Snapshot(t *testing.T) {
	t.Parallel()

	m := &Metrics{}
	m.RequestsTotal.Store(10)
	m.RequestsThrottled.Store(2)
	m.RequestsQueued.Store(1)
	m.RequestsSuccess.Store(7)
	m.RequestsError.Store(3)
	m.RetriesTotal.Store(4)
	m.FailoversTotal.Store(1)
	m.Instances429.Store(5)
	m.Instances529.Store(2)

	snap := m.Snapshot()

	expected := map[string]int64{
		"requests_total":     10,
		"requests_throttled": 2,
		"requests_queued":    1,
		"requests_success":   7,
		"requests_error":     3,
		"retries_total":      4,
		"failovers_total":    1,
		"instances_429":      5,
		"instances_529":      2,
	}

	for k, want := range expected {
		if got := snap[k]; got != want {
			t.Errorf("snap[%q] = %d, want %d", k, got, want)
		}
	}
}

func TestMetrics_ConcurrentAddSnapshot(t *testing.T) {
	t.Parallel()

	m := &Metrics{}
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Writers
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RequestsTotal.Add(1)
				m.RequestsSuccess.Add(1)
				m.RetriesTotal.Add(1)
			}
		}()
	}

	// Reader (concurrent with writers)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			snap := m.Snapshot()
			// Values should be non-negative
			for k, v := range snap {
				if v < 0 {
					t.Errorf("snap[%q] = %d, want >= 0", k, v)
				}
			}
		}
	}()

	wg.Wait()

	// Final values should equal goroutines * iterations
	want := int64(goroutines * iterations)
	if got := m.RequestsTotal.Load(); got != want {
		t.Errorf("RequestsTotal = %d, want %d", got, want)
	}
}

func TestInstanceMetrics(t *testing.T) {
	t.Parallel()
	m := &Metrics{}

	im1 := m.Instance("acct-1")
	if im1 == nil {
		t.Fatal("Instance returned nil")
	}

	// Same pointer on repeated access
	im2 := m.Instance("acct-1")
	if im1 != im2 {
		t.Fatal("Instance returned different pointer for same name")
	}

	// Different instance returns different pointer
	im3 := m.Instance("acct-2")
	if im1 == im3 {
		t.Fatal("Different instances returned same pointer")
	}

	im1.RequestsTotal.Add(5)
	im1.RequestsSuccess.Add(3)
	im1.RequestsError.Add(2)
	im1.Errors429.Add(1)
	im1.Errors529.Add(1)

	if im1.RequestsTotal.Load() != 5 {
		t.Fatalf("expected 5, got %d", im1.RequestsTotal.Load())
	}
}

func TestMetrics_StartPeriodicLog(t *testing.T) {
	t.Parallel()

	m := &Metrics{}
	m.RequestsTotal.Store(42)

	ctx, cancel := context.WithCancel(context.Background())

	// Start with very short interval
	m.StartPeriodicLog(ctx, 10*time.Millisecond)

	// Let it tick a couple times
	time.Sleep(50 * time.Millisecond)

	// Cancel should stop the goroutine
	cancel()
	time.Sleep(20 * time.Millisecond)

	// No panic or race = pass
}
