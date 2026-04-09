package loadbalancer

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestAccountHealth_IsBanned(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		reason string
		want   bool
	}{
		{name: "platform forbidden", reason: PlatformBanReasonForbidden, want: true},
		{name: "oauth not allowed", reason: PlatformBanReasonOAuthNotAllowed, want: true},
		{name: "organization disabled", reason: PlatformBanReasonOrganizationDisabled, want: true},
		{name: "legacy forbidden", reason: legacyBanReasonForbidden, want: true},
		{name: "consecutive 401", reason: "consecutive_401", want: false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := NewAccountHealth("test-id", "test")
			h.Disable(tt.reason)

			if got := h.IsBanned(); got != tt.want {
				t.Fatalf("IsBanned() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccountHealth_BanReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		reason string
		want   string
	}{
		{name: "platform forbidden", reason: PlatformBanReasonForbidden, want: PlatformBanReasonForbidden},
		{name: "oauth not allowed", reason: PlatformBanReasonOAuthNotAllowed, want: PlatformBanReasonOAuthNotAllowed},
		{name: "organization disabled", reason: PlatformBanReasonOrganizationDisabled, want: PlatformBanReasonOrganizationDisabled},
		{name: "legacy forbidden", reason: legacyBanReasonForbidden, want: PlatformBanReasonForbidden},
		{name: "consecutive 401", reason: "consecutive_401", want: ""},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			h := NewAccountHealth("test-id", "test")
			h.Disable(tt.reason)

			if got := h.BanReason(); got != tt.want {
				t.Fatalf("BanReason() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCooldown_429WithRetryAfter(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

	// 429 without reset headers → soft cooldown
	h.RecordError(context.Background(), 429, 60*time.Second, nil)
	if h.IsAvailable() {
		t.Error("should be unavailable during cooldown")
	}
}

func TestCooldown_429WithResetHeaders(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

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
	h := NewAccountHealth("test-id", "test")

	// Set a very short cooldown
	h.SetCooldown(1*time.Millisecond, "test")
	time.Sleep(5 * time.Millisecond)
	if !h.IsAvailable() {
		t.Error("should be available after cooldown expires")
	}
}

func TestDisable_403(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

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
	h := NewAccountHealth("test-id", "test")

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
	h := NewAccountHealth("test-id", "test")

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

	// Cold start: no errors, no latency, no util → score from load only + jitter
	h := NewAccountHealth("test-id", "test")
	base := 0.0*0.3 + 0.0*0.2 + 0.5*0.2 + 0.0*0.3 // errorRate=0, latency=0, loadRate=50%, util=0
	// With ±5% jitter, score should be within [base*0.95, base*1.05]
	score := h.Score(50)
	if score < base*0.95-0.001 || score > base*1.05+0.001 {
		t.Errorf("expected score ~%.2f (±5%%), got %.2f", base, score)
	}

	// With errors, score should increase significantly
	h.RecordError(context.Background(), 500, 0, nil)
	h.RecordError(context.Background(), 500, 0, nil)
	scoreWithErrors := h.Score(50)
	// Error rate pushes base well above cold start; verify meaningful increase
	// even accounting for ±5% jitter on both values
	if scoreWithErrors <= base*1.05+0.001 {
		t.Errorf("score with errors (%.4f) should be significantly > cold start base (%.4f)", scoreWithErrors, base)
	}
}

func TestScore_Jitter(t *testing.T) {
	t.Parallel()

	h := NewAccountHealth("test-id", "test")
	// Set some non-zero budget util so scores aren't near zero
	h.budget.mu.Lock()
	h.budget.window7d.Utilization = 0.50
	h.budget.mu.Unlock()

	// Call Score many times and verify not all identical (jitter working)
	scores := make(map[float64]bool)
	for i := 0; i < 50; i++ {
		s := h.Score(30)
		scores[s] = true
	}
	if len(scores) < 5 {
		t.Errorf("expected jitter to produce varied scores, got only %d distinct values out of 50", len(scores))
	}
}

func TestNewAccountHealth_Defaults(t *testing.T) {
	t.Parallel()

	h := NewAccountHealth("test-id", "test")
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
	h := NewAccountHealth("test-id", "test")

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
	h := NewAccountHealth("test-id", "test")

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

func TestEnable_Consecutive401(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

	// Disable via consecutive 401s
	h.Disable("consecutive_401")
	if !h.IsDisabled() {
		t.Fatal("expected disabled")
	}

	// Enable should succeed
	if !h.Enable() {
		t.Error("expected Enable to return true")
	}
	if h.IsDisabled() {
		t.Error("expected account to be enabled after Enable()")
	}
	if h.DisabledReason() != "" {
		t.Errorf("expected empty reason, got %q", h.DisabledReason())
	}
	if !h.IsAvailable() {
		t.Error("expected account to be available after Enable()")
	}
}

func TestEnable_PlatformBan(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

	// Disable via platform ban
	h.Disable(PlatformBanReasonForbidden)
	if !h.IsDisabled() {
		t.Fatal("expected disabled")
	}

	// Enable should still succeed for banned accounts (UI manual recovery)
	if !h.Enable() {
		t.Error("expected Enable to return true even for banned accounts")
	}
	if h.IsDisabled() {
		t.Error("expected account to be enabled after Enable()")
	}
	if h.IsBanned() {
		t.Error("expected account to not be banned after Enable()")
	}
}

func TestEnable_NotDisabled(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

	// Enable on already-enabled account should return false
	if h.Enable() {
		t.Error("expected Enable to return false for non-disabled account")
	}
}

func TestRecordTimeout(t *testing.T) {
	t.Parallel()
	h := NewAccountHealth("test-id", "test")

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
