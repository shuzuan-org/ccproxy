package loadbalancer

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestCooldown_429WithRetryAfter(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// 429 without reset headers → soft cooldown
	h.RecordError(context.Background(), 429, 60*time.Second, nil)
	if h.IsAvailable() {
		t.Error("should be unavailable during cooldown")
	}
}

func TestCooldown_429WithResetHeaders(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-reset", "2026-03-14T12:00:00Z")
	h.RecordError(context.Background(), 429, 0, headers)
	if h.IsAvailable() {
		t.Error("should be unavailable during cooldown from true 429")
	}
	// Budget should have recorded the 429
	if h.budget.Consecutive429() != 1 {
		t.Errorf("expected 1 consecutive 429, got %d", h.budget.Consecutive429())
	}
}

func TestCooldown_Expiry(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// Set a very short cooldown
	h.SetCooldown(1*time.Millisecond, "test")
	time.Sleep(5 * time.Millisecond)
	if !h.IsAvailable() {
		t.Error("should be available after cooldown expires")
	}
}

func TestDisable_403(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	h.RecordError(context.Background(), 403, 0, nil)
	if h.IsAvailable() {
		t.Error("should be disabled after 403")
	}
	if !h.IsDisabled() {
		t.Error("should be permanently disabled")
	}
	if h.DisabledReason() != "forbidden" {
		t.Errorf("expected reason 'forbidden', got %q", h.DisabledReason())
	}
}

func TestErrorRate_SlidingWindow(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// Record 3 successes and 1 error
	h.RecordSuccess(context.Background(), 1000)
	h.RecordSuccess(context.Background(), 1000)
	h.RecordSuccess(context.Background(), 1000)
	h.RecordError(context.Background(), 500, 0, nil)

	rate := h.ErrorRate()
	want := 0.25 // 1/4
	if rate < want-0.01 || rate > want+0.01 {
		t.Errorf("expected error rate ~%.2f, got %.2f", want, rate)
	}
}

func TestLatencyEMA_Convergence(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// First measurement initializes
	h.RecordSuccess(context.Background(), 1000)
	if h.LatencyEMA() != 1000 {
		t.Errorf("expected initial latency 1000, got %d", h.LatencyEMA())
	}

	// Feed many high-latency values; EMA should converge upward
	for i := 0; i < 50; i++ {
		h.RecordSuccess(context.Background(), 5000)
	}
	ema := h.LatencyEMA()
	if ema < 4000 {
		t.Errorf("expected EMA to converge toward 5000, got %d", ema)
	}
}

func TestScore_Composite(t *testing.T) {
	t.Parallel()

	// Cold start: no errors, no latency, no util → score from load only
	h := NewAccountHealth("test")
	score := h.Score(50)
	// New weights: errRate*0.3 + latency*0.2 + loadRate*0.2 + maxUtil*0.3
	want := 0.0*0.3 + 0.0*0.2 + 0.5*0.2 + 0.0*0.3 // errorRate=0, latency=0, loadRate=50%, util=0
	if score < want-0.01 || score > want+0.01 {
		t.Errorf("expected score ~%.2f, got %.2f", want, score)
	}

	// With errors, score should increase
	h.RecordError(context.Background(), 500, 0, nil)
	h.RecordError(context.Background(), 500, 0, nil)
	scoreWithErrors := h.Score(50)
	if scoreWithErrors <= score {
		t.Errorf("score with errors (%.2f) should be > cold start score (%.2f)", scoreWithErrors, score)
	}
}

func TestNewAccountHealth_Defaults(t *testing.T) {
	t.Parallel()

	h := NewAccountHealth("test")
	if !h.IsAvailable() {
		t.Error("new health should be available")
	}
	if h.ErrorRate() != 0 {
		t.Error("new health should have 0 error rate")
	}
	if h.budget == nil {
		t.Error("new health should have a budget controller")
	}
}

func TestRecordSuccess_ResetsCounters(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// Record some errors first
	h.RecordError(context.Background(), 529, 0, nil)
	h.RecordError(context.Background(), 529, 0, nil)
	if h.Consecutive529() != 2 {
		t.Errorf("expected 2 consecutive 529s, got %d", h.Consecutive529())
	}

	// Success should reset
	h.RecordSuccess(context.Background(), 1000)
	if h.Consecutive529() != 0 {
		t.Errorf("expected 0 consecutive 529s after success, got %d", h.Consecutive529())
	}
}

func TestConsecutive401_Disable(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// 3 consecutive 401s within 5 minutes should disable
	h.RecordError(context.Background(), 401, 0, nil)
	h.RecordError(context.Background(), 401, 0, nil)
	h.RecordError(context.Background(), 401, 0, nil)

	if !h.IsDisabled() {
		t.Error("expected account to be disabled after 3 consecutive 401s")
	}
	if h.DisabledReason() != "consecutive_401" {
		t.Errorf("expected reason 'consecutive_401', got %q", h.DisabledReason())
	}
}

func TestRecordTimeout(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	// 3 timeouts should trigger cooldown
	h.RecordTimeout(context.Background())
	h.RecordTimeout(context.Background())
	if !h.IsAvailable() {
		t.Error("should still be available after 2 timeouts")
	}
	h.RecordTimeout(context.Background())
	if h.IsAvailable() {
		t.Error("should be in cooldown after 3 timeouts")
	}
}
