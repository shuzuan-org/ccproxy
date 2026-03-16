package loadbalancer

import (
	"context"
	"testing"
	"time"
)

func TestPoolThrottle_ShouldThrottle_NoRequests(t *testing.T) {
	t.Parallel()
	pt := NewPoolThrottle(10)
	if pt.ShouldThrottle() {
		t.Error("should not throttle with no requests")
	}
}

func TestPoolThrottle_ShouldThrottle_ColdWindow(t *testing.T) {
	t.Parallel()
	pt := NewPoolThrottle(10)

	// 1 request, 0 accepts — should NOT throttle (below minThrottleSamples=3)
	pt.RecordRequest()
	for i := 0; i < 100; i++ {
		if pt.ShouldThrottle() {
			t.Error("should not throttle with only 1 request (below minThrottleSamples)")
		}
	}

	// 2 requests, 0 accepts — still below threshold
	pt.RecordRequest()
	for i := 0; i < 100; i++ {
		if pt.ShouldThrottle() {
			t.Error("should not throttle with only 2 requests (below minThrottleSamples)")
		}
	}
}

func TestPoolThrottle_ShouldThrottle_AllAccepted(t *testing.T) {
	t.Parallel()
	pt := NewPoolThrottle(10)
	// Record equal requests and accepts — formula yields 0
	for i := 0; i < 10; i++ {
		pt.RecordRequest()
		pt.RecordAccept()
	}
	// With K=2.0 and requests==accepts, (10 - 2*10)/(10+1) < 0, so never throttle
	for i := 0; i < 100; i++ {
		if pt.ShouldThrottle() {
			t.Error("should not throttle when accepts >= requests/K")
		}
	}
}

func TestPoolThrottle_ShouldThrottle_HighErrorRate(t *testing.T) {
	t.Parallel()
	pt := NewPoolThrottle(10)
	// Many requests, no accepts → high throttle probability
	for i := 0; i < 100; i++ {
		pt.RecordRequest()
	}
	// With 100 requests and 0 accepts: (100 - 0) / 101 ≈ 0.99
	throttled := 0
	for i := 0; i < 100; i++ {
		if pt.ShouldThrottle() {
			throttled++
		}
	}
	if throttled < 80 {
		t.Errorf("expected high throttle rate, got %d/100", throttled)
	}
}

func TestPoolThrottle_EnqueueDequeue(t *testing.T) {
	t.Parallel()
	// Use a throttle with small queue. Note: NewPoolThrottle enforces min 10.
	pt := &PoolThrottle{
		K:     defaultThrottleK,
		queue: make(chan struct{}, 2),
	}

	ctx := context.Background()
	if !pt.Enqueue(ctx, false) {
		t.Error("first enqueue should succeed")
	}
	if !pt.Enqueue(ctx, false) {
		t.Error("second enqueue should succeed")
	}

	// Third should timeout (queue full)
	ctx2, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if pt.Enqueue(ctx2, false) {
		t.Error("third enqueue should fail (queue full)")
	}

	// Dequeue one and try again
	pt.Dequeue()
	if !pt.Enqueue(ctx, false) {
		t.Error("enqueue after dequeue should succeed")
	}
}

func TestPoolThrottle_EnqueueContextCancelled(t *testing.T) {
	t.Parallel()
	pt := &PoolThrottle{
		K:     defaultThrottleK,
		queue: make(chan struct{}, 1),
	}
	ctx := context.Background()
	pt.Enqueue(ctx, false) // fill queue

	ctx2, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	if pt.Enqueue(ctx2, false) {
		t.Error("enqueue with cancelled context should fail")
	}
}

func TestPoolUtilization(t *testing.T) {
	t.Parallel()

	t.Run("empty budgets", func(t *testing.T) {
		t.Parallel()
		if got := PoolUtilization(nil); got != 0 {
			t.Errorf("PoolUtilization(nil) = %f, want 0", got)
		}
	})

	t.Run("average calculation", func(t *testing.T) {
		t.Parallel()
		b1 := NewBudgetController("test1")
		b1.mu.Lock()
		b1.window5h.Utilization = 0.40
		b1.mu.Unlock()

		b2 := NewBudgetController("test2")
		b2.mu.Lock()
		b2.window5h.Utilization = 0.80
		b2.mu.Unlock()

		budgets := map[string]*BudgetController{"a": b1, "b": b2}
		got := PoolUtilization(budgets)
		// avg(0.40, 0.80) = 0.60
		if abs(got-0.60) > 0.001 {
			t.Errorf("PoolUtilization = %f, want 0.60", got)
		}
	})
}

func TestUtilizationDelay(t *testing.T) {
	t.Parallel()

	t.Run("below threshold no delay", func(t *testing.T) {
		t.Parallel()
		if d := UtilizationDelay(0.3); d != 0 {
			t.Errorf("UtilizationDelay(0.3) = %v, want 0", d)
		}
	})

	t.Run("at 0.5 near zero delay", func(t *testing.T) {
		t.Parallel()
		// At exactly 0.5: (0/0.5)^2 * 5s = 0, but jitter may add tiny amount
		d := UtilizationDelay(0.5)
		if d > 100*time.Millisecond {
			t.Errorf("UtilizationDelay(0.5) = %v, expected near zero", d)
		}
	})

	t.Run("at 1.0 max delay around 5s", func(t *testing.T) {
		t.Parallel()
		// At 1.0: (0.5/0.5)^2 * 5s = 5s ± 15%
		delays := make([]time.Duration, 20)
		for i := range delays {
			delays[i] = UtilizationDelay(1.0)
		}
		for _, d := range delays {
			if d < 4*time.Second || d > 6*time.Second {
				t.Errorf("UtilizationDelay(1.0) = %v, expected 4-6s range", d)
			}
		}
	})

	t.Run("monotonically increasing", func(t *testing.T) {
		t.Parallel()
		var prev time.Duration
		for u := 0.5; u <= 1.0; u += 0.1 {
			// Take average of multiple samples to smooth jitter
			var sum time.Duration
			n := 50
			for i := 0; i < n; i++ {
				sum += UtilizationDelay(u)
			}
			avg := sum / time.Duration(n)
			if avg < prev-100*time.Millisecond { // small tolerance for jitter
				t.Errorf("delay not monotonic: util=%.1f avg=%v < prev=%v", u, avg, prev)
			}
			prev = avg
		}
	})
}

func TestPoolThrottle_WindowPruning(t *testing.T) {
	t.Parallel()
	pt := NewPoolThrottle(10)

	// Add old entries
	pt.mu.Lock()
	old := time.Now().Add(-3 * time.Minute)
	pt.requests = append(pt.requests, old, old, old)
	pt.accepts = append(pt.accepts, old, old, old)
	pt.mu.Unlock()

	// ShouldThrottle should prune old entries
	pt.ShouldThrottle()

	pt.mu.Lock()
	reqs := len(pt.requests)
	accs := len(pt.accepts)
	pt.mu.Unlock()

	if reqs != 0 {
		t.Errorf("requests after prune = %d, want 0", reqs)
	}
	if accs != 0 {
		t.Errorf("accepts after prune = %d, want 0", accs)
	}
}
