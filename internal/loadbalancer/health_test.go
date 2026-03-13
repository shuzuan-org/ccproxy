package loadbalancer

import (
	"testing"
	"time"
)

func TestCooldown_429WithRetryAfter(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test")

	h.RecordError(429, 60*time.Second)
	if h.IsAvailable() {
		t.Error("should be unavailable during cooldown")
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

	h.RecordError(403, 0)
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
	h.RecordSuccess(1000)
	h.RecordSuccess(1000)
	h.RecordSuccess(1000)
	h.RecordError(500, 0)

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
	h.RecordSuccess(1000)
	if h.LatencyEMA() != 1000 {
		t.Errorf("expected initial latency 1000, got %d", h.LatencyEMA())
	}

	// Feed many high-latency values; EMA should converge upward
	for i := 0; i < 50; i++ {
		h.RecordSuccess(5000)
	}
	ema := h.LatencyEMA()
	if ema < 4000 {
		t.Errorf("expected EMA to converge toward 5000, got %d", ema)
	}
}

func TestScore_Composite(t *testing.T) {
	t.Parallel()

	// Cold start: no errors, no latency → score from load only
	h := NewAccountHealth("test")
	score := h.Score(50)
	want := 0.0*0.4 + 0.0*0.3 + 0.5*0.3 // errorRate=0, latency=0, loadRate=50%
	if score < want-0.01 || score > want+0.01 {
		t.Errorf("expected score ~%.2f, got %.2f", want, score)
	}

	// With errors, score should increase
	h.RecordError(500, 0)
	h.RecordError(500, 0)
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
}
