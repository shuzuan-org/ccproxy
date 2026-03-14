package loadbalancer

import (
	"net/http"
	"testing"
	"time"
)

func TestBudgetController_UpdateFromHeaders(t *testing.T) {
	t.Parallel()

	bc := NewBudgetController("test")
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-5h-utilization", "0.45")
	h.Set("anthropic-ratelimit-unified-5h-status", "allowed")
	h.Set("anthropic-ratelimit-unified-5h-reset", "2026-03-14T12:00:00Z")
	h.Set("anthropic-ratelimit-unified-7d-utilization", "0.30")
	h.Set("anthropic-ratelimit-unified-7d-status", "allowed")
	h.Set("anthropic-ratelimit-unified-7d-reset", "2026-03-20T00:00:00Z")

	bc.UpdateFromHeaders(h)

	w5 := bc.Window5h()
	w7 := bc.Window7d()

	if w5.Utilization != 0.45 {
		t.Errorf("5h utilization = %f, want 0.45", w5.Utilization)
	}
	if w5.Status != "allowed" {
		t.Errorf("5h status = %q, want %q", w5.Status, "allowed")
	}
	if w7.Utilization != 0.30 {
		t.Errorf("7d utilization = %f, want 0.30", w7.Utilization)
	}
	if w5.LastUpdated.IsZero() {
		t.Error("5h LastUpdated should not be zero")
	}
	if w7.LastUpdated.IsZero() {
		t.Error("7d LastUpdated should not be zero")
	}
}

func TestBudgetController_UpdateFromUsageAPI(t *testing.T) {
	t.Parallel()

	bc := NewBudgetController("test")
	bc.UpdateFromUsageAPI(
		UsageAPIWindow{Utilization: 50, ResetsAt: "2026-03-14T12:00:00Z"},
		UsageAPIWindow{Utilization: 75, ResetsAt: "2026-03-20T00:00:00Z"},
	)

	w5 := bc.Window5h()
	w7 := bc.Window7d()

	if w5.Utilization != 0.50 {
		t.Errorf("5h utilization = %f, want 0.50 (normalized from 50)", w5.Utilization)
	}
	if w7.Utilization != 0.75 {
		t.Errorf("7d utilization = %f, want 0.75 (normalized from 75)", w7.Utilization)
	}
}

func TestBudgetController_StateThresholds(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		util5h   float64
		util7d   float64
		penalty  float64
		expected SchedulingState
	}{
		{"low utilization", 0.20, 0.10, 0, StateNormal},
		{"at normal threshold", 0.60, 0.10, 0, StateStickyOnly},
		{"between thresholds", 0.70, 0.10, 0, StateStickyOnly},
		{"at danger threshold", 0.80, 0.10, 0, StateBlocked},
		{"high utilization", 0.95, 0.10, 0, StateBlocked},
		{"7d drives state", 0.10, 0.85, 0, StateBlocked},
		{"penalty shifts threshold down", 0.55, 0.10, 0.06, StateStickyOnly}, // 0.60-0.06=0.54, 0.55>=0.54
		{"penalty makes blocked", 0.70, 0.10, 0.12, StateBlocked},           // 0.80-0.12=0.68, 0.70>=0.68
		{"just below normal", 0.59, 0.10, 0, StateNormal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bc := NewBudgetController("test")
			bc.mu.Lock()
			bc.window5h.Utilization = tt.util5h
			bc.window7d.Utilization = tt.util7d
			bc.penaltyShift = tt.penalty
			bc.mu.Unlock()

			got := bc.State()
			if got != tt.expected {
				t.Errorf("State() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestBudgetController_Record429_TrueVsFake(t *testing.T) {
	t.Parallel()

	t.Run("true 429 increases penalty", func(t *testing.T) {
		t.Parallel()
		bc := NewBudgetController("test")
		bc.Record429(true)
		if bc.Consecutive429() != 1 {
			t.Errorf("consecutive429 = %d, want 1", bc.Consecutive429())
		}
		if bc.PenaltyShift() != penaltyStep {
			t.Errorf("penaltyShift = %f, want %f", bc.PenaltyShift(), penaltyStep)
		}
	})

	t.Run("fake 429 does nothing", func(t *testing.T) {
		t.Parallel()
		bc := NewBudgetController("test")
		bc.Record429(false)
		if bc.Consecutive429() != 0 {
			t.Errorf("consecutive429 = %d, want 0", bc.Consecutive429())
		}
		if bc.PenaltyShift() != 0 {
			t.Errorf("penaltyShift = %f, want 0", bc.PenaltyShift())
		}
	})

	t.Run("penalty capped at max", func(t *testing.T) {
		t.Parallel()
		bc := NewBudgetController("test")
		for i := 0; i < 10; i++ {
			bc.Record429(true)
		}
		if bc.PenaltyShift() != penaltyMax {
			t.Errorf("penaltyShift = %f, want cap %f", bc.PenaltyShift(), penaltyMax)
		}
	})
}

func TestBudgetController_RecordSuccess_Recovery(t *testing.T) {
	t.Parallel()

	bc := NewBudgetController("test")
	// Record 3 true 429s
	bc.Record429(true)
	bc.Record429(true)
	bc.Record429(true)
	if bc.Consecutive429() != 3 {
		t.Fatalf("consecutive429 = %d, want 3", bc.Consecutive429())
	}

	// Success too soon doesn't recover
	bc.RecordSuccess()
	if bc.Consecutive429() != 3 {
		t.Errorf("consecutive429 = %d, want 3 (too soon to recover)", bc.Consecutive429())
	}

	// Simulate time passing beyond recovery interval
	bc.mu.Lock()
	bc.lastPenaltyAt = time.Now().Add(-penaltyRecoveryInterval - time.Second)
	bc.mu.Unlock()

	bc.RecordSuccess()
	if bc.Consecutive429() != 2 {
		t.Errorf("consecutive429 = %d, want 2 (should have recovered by 1)", bc.Consecutive429())
	}
	expectedPenalty := penaltyStep * 2
	if abs(bc.PenaltyShift()-expectedPenalty) > 0.001 {
		t.Errorf("penaltyShift = %f, want %f", bc.PenaltyShift(), expectedPenalty)
	}
}

func TestBudgetController_DynamicMaxConcurrency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		maxUtil   float64
		hardLimit int
		expected  int
	}{
		{"very low util", 0.20, 10, 8},
		{"below 0.5", 0.49, 10, 8},
		{"at 0.5", 0.50, 10, 5},
		{"at 0.7", 0.70, 10, 3},
		{"at 0.85", 0.85, 10, 1},
		{"at 0.95", 0.95, 10, 1},
		{"hard limit constrains", 0.20, 3, 3},
		{"hard limit 0 means no limit", 0.20, 0, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			bc := NewBudgetController("test")
			bc.mu.Lock()
			bc.window5h.Utilization = tt.maxUtil
			bc.mu.Unlock()

			got := bc.DynamicMaxConcurrency(tt.hardLimit)
			if got != tt.expected {
				t.Errorf("DynamicMaxConcurrency(%d) = %d, want %d", tt.hardLimit, got, tt.expected)
			}
		})
	}
}

func TestBudgetController_MaxUtilization(t *testing.T) {
	t.Parallel()

	bc := NewBudgetController("test")
	bc.mu.Lock()
	bc.window5h.Utilization = 0.30
	bc.window7d.Utilization = 0.70
	bc.mu.Unlock()

	if got := bc.MaxUtilization(); got != 0.70 {
		t.Errorf("MaxUtilization() = %f, want 0.70", got)
	}
}

func TestBudgetController_HasRecentData(t *testing.T) {
	t.Parallel()

	bc := NewBudgetController("test")
	if bc.HasRecentData(5 * time.Minute) {
		t.Error("should not have recent data initially")
	}

	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-5h-utilization", "0.1")
	bc.UpdateFromHeaders(h)

	if !bc.HasRecentData(5 * time.Minute) {
		t.Error("should have recent data after update")
	}
}

func TestBudgetController_CooldownUntil(t *testing.T) {
	t.Parallel()

	bc := NewBudgetController("test")
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-5h-reset", "2026-03-14T12:00:00Z")
	h.Set("anthropic-ratelimit-unified-7d-reset", "2026-03-14T14:00:00Z")
	bc.UpdateFromHeaders(h)

	cd := bc.CooldownUntil()
	expected, _ := time.Parse(time.RFC3339, "2026-03-14T14:00:00Z")
	if !cd.Equal(expected) {
		t.Errorf("CooldownUntil() = %v, want %v", cd, expected)
	}
}

func TestEffectiveMaxConcurrency(t *testing.T) {
	t.Parallel()

	t.Run("nil budget returns hardLimit", func(t *testing.T) {
		t.Parallel()
		if got := EffectiveMaxConcurrency(nil, 5); got != 5 {
			t.Errorf("EffectiveMaxConcurrency(nil, 5) = %d, want 5", got)
		}
	})

	t.Run("with budget delegates", func(t *testing.T) {
		t.Parallel()
		bc := NewBudgetController("test")
		bc.mu.Lock()
		bc.window5h.Utilization = 0.90
		bc.mu.Unlock()
		if got := EffectiveMaxConcurrency(bc, 5); got != 1 {
			t.Errorf("EffectiveMaxConcurrency(bc, 5) = %d, want 1", got)
		}
	})
}

func TestClamp01(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in, out float64
	}{
		{-0.5, 0},
		{0, 0},
		{0.5, 0.5},
		{1.0, 1.0},
		{1.5, 1.0},
	}
	for _, tt := range tests {
		if got := clamp01(tt.in); got != tt.out {
			t.Errorf("clamp01(%f) = %f, want %f", tt.in, got, tt.out)
		}
	}
}

func abs(f float64) float64 {
	if f < 0 {
		return -f
	}
	return f
}
