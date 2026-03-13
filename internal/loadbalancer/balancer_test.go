package loadbalancer

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

// helpers

func boolPtr(b bool) *bool { return &b }

func makeInstance(name string, maxConc int) config.InstanceConfig {
	return config.InstanceConfig{
		Name:           name,
		MaxConcurrency: maxConc,
		BaseURL:        "https://api.anthropic.com",
		RequestTimeout: 300,
	}
}

func makeDisabledInstance(name string) config.InstanceConfig {
	inst := makeInstance(name, 5)
	inst.Enabled = boolPtr(false)
	return inst
}

func newTestBalancer(instances []config.InstanceConfig) *Balancer {
	tracker := NewConcurrencyTracker()
	return NewBalancer(instances, tracker)
}

// Test 1: Single instance → always selected
func TestBalancer_SingleInstance(t *testing.T) {
	b := newTestBalancer([]config.InstanceConfig{makeInstance("inst1", 5)})

	result, err := b.SelectInstance("", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name != "inst1" {
		t.Errorf("expected inst1, got %s", result.Instance.Name)
	}
	result.Release()
}

// Test 2: Instance with errors gets lower score → healthy instance preferred
func TestBalancer_ScoreBasedOrder(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("unhealthy", 5),
		makeInstance("healthy", 5),
	}
	b := newTestBalancer(instances)

	// Record errors on "unhealthy" to give it a worse score
	b.ReportResult("unhealthy", 500, 1000, 0)
	b.ReportResult("unhealthy", 500, 1000, 0)
	// Clear cooldown so instance is available but has high error rate
	h := b.GetHealth("unhealthy")
	h.mu.Lock()
	h.cooldownUntil = time.Time{}
	h.mu.Unlock()

	result, err := b.SelectInstance("", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name != "healthy" {
		t.Errorf("expected healthy (lower score), got %s", result.Instance.Name)
	}
	result.Release()
}

// Test 3: Same priority → weighted by load rate (lower load first)
func TestBalancer_LoadRateOrder(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 4),
		makeInstance("inst-b", 4),
	}
	b := newTestBalancer(instances)

	// Fill inst-a with 2 slots (50% load)
	r1, _ := b.tracker.Acquire("inst-a", "req1", 4)
	r2, _ := b.tracker.Acquire("inst-a", "req2", 4)
	defer r1()
	defer r2()

	// inst-b is at 0% load → should be selected
	result, err := b.SelectInstance("", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name != "inst-b" {
		t.Errorf("expected inst-b (lower load), got %s", result.Instance.Name)
	}
	result.Release()
}

// Test 4: Session sticky: same sessionKey → same instance within TTL
func TestBalancer_StickySession(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 5),
		makeInstance("inst-b", 5),
	}
	b := newTestBalancer(instances)

	// First selection
	r1, err := b.SelectInstance("session-1", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	firstInstance := r1.Instance.Name
	r1.Release()

	// Bind session
	b.BindSession("session-1", firstInstance)

	// Second selection with same session key → same instance
	r2, err := b.SelectInstance("session-1", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error on second select: %v", err)
	}
	if r2.Instance.Name != firstInstance {
		t.Errorf("expected sticky instance %s, got %s", firstInstance, r2.Instance.Name)
	}
	r2.Release()
}

// Test 5: Session expired → new selection (may differ)
func TestBalancer_SessionExpired(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 5),
	}
	b := newTestBalancer(instances)

	// Manually insert an expired session
	b.sessions.Store("old-session", &SessionInfo{
		InstanceName: "inst-a",
		LastRequest:  time.Now().Add(-(sessionTTL + time.Second)),
	})

	// Should still work (expired session cleared, fallback to layer 2)
	result, err := b.SelectInstance("old-session", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.Release()

	// Session should be gone
	if _, ok := b.sessions.Load("old-session"); ok {
		t.Error("expired session should have been deleted")
	}
}

// Test 6: Sticky instance at capacity → falls through to Layer 2
func TestBalancer_StickyAtCapacity(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 1), // capacity=1
		makeInstance("inst-b", 5),
	}
	b := newTestBalancer(instances)

	// Bind session to inst-a
	b.BindSession("session-x", "inst-a")

	// Fill inst-a to capacity
	r1, ok := b.tracker.Acquire("inst-a", "blocker", 1)
	if !ok {
		t.Fatal("blocker acquire should succeed")
	}
	defer r1()

	// Session points to inst-a but it's full → should fall through to inst-b
	result, err := b.SelectInstance("session-x", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name != "inst-b" {
		t.Errorf("expected fallback to inst-b, got %s", result.Instance.Name)
	}
	result.Release()
}

// Test 7: Exclude failed instances
func TestBalancer_ExcludeInstances(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 5),
		makeInstance("inst-b", 5),
	}
	b := newTestBalancer(instances)

	result, err := b.SelectInstance("", map[string]bool{"inst-a": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name == "inst-a" {
		t.Error("inst-a should be excluded")
	}
	result.Release()
}

// Test 8: All instances at capacity → returns ErrAllInstancesBusy
func TestBalancer_AllBusy(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 1),
		makeInstance("inst-b", 1),
	}
	b := newTestBalancer(instances)

	// Fill both to capacity
	r1, _ := b.tracker.Acquire("inst-a", "block-a", 1)
	r2, _ := b.tracker.Acquire("inst-b", "block-b", 1)
	defer r1()
	defer r2()

	_, err := b.SelectInstance("", map[string]bool{})
	if err != ErrAllInstancesBusy {
		t.Errorf("expected ErrAllInstancesBusy, got %v", err)
	}
}

// Test 9: BindSession + SelectInstance → returns sticky instance
func TestBalancer_BindThenSelect(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 5),
		makeInstance("inst-b", 5), // lower priority
	}
	b := newTestBalancer(instances)

	// Bind to higher-priority-value instance (inst-b)
	b.BindSession("my-session", "inst-b")

	result, err := b.SelectInstance("my-session", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Sticky should override normal priority ordering
	if result.Instance.Name != "inst-b" {
		t.Errorf("expected sticky inst-b, got %s", result.Instance.Name)
	}
	result.Release()
}

// Test 10: UpdateInstances replaces list
func TestBalancer_UpdateInstances(t *testing.T) {
	b := newTestBalancer([]config.InstanceConfig{makeInstance("inst-a", 5)})

	newInstances := []config.InstanceConfig{
		makeInstance("inst-x", 5),
		makeInstance("inst-y", 5),
	}
	b.UpdateInstances(newInstances)

	got := b.GetInstances()
	if len(got) != 2 {
		t.Fatalf("expected 2 instances after update, got %d", len(got))
	}

	// Disabled instances should be filtered out
	withDisabled := append(newInstances, makeDisabledInstance("inst-disabled"))
	b.UpdateInstances(withDisabled)
	got = b.GetInstances()
	if len(got) != 2 {
		t.Errorf("expected 2 enabled instances, got %d", len(got))
	}
}

// Test 11: Concurrent SelectInstance (race test)
func TestBalancer_ConcurrentSelect(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 10),
		makeInstance("inst-b", 10),
	}
	b := newTestBalancer(instances)

	var wg sync.WaitGroup
	goroutines := 30

	wg.Add(goroutines + 5)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, err := b.SelectInstance("", map[string]bool{})
			if err != nil {
				return // acceptable if all slots are briefly full
			}
			// Simulate short work then release
			time.Sleep(time.Millisecond)
			result.Release()
		}()
	}

	// Concurrent UpdateInstances to trigger race detector
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			b.UpdateInstances(instances)
		}()
	}

	wg.Wait()
}

// Test: No healthy instances → ErrNoHealthyInstances
func TestBalancer_NoInstances(t *testing.T) {
	b := newTestBalancer([]config.InstanceConfig{})
	_, err := b.SelectInstance("", map[string]bool{})
	if err != ErrNoHealthyInstances {
		t.Errorf("expected ErrNoHealthyInstances, got %v", err)
	}
}

// Test: filterEnabled removes disabled instances
func TestBalancer_FilterEnabled(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("enabled", 5),
		makeDisabledInstance("disabled"),
	}
	b := newTestBalancer(instances)
	got := b.GetInstances()
	if len(got) != 1 || got[0].Name != "enabled" {
		t.Errorf("expected only enabled instance, got %v", got)
	}
}

// Test: StartCleanup runs without panic
func TestBalancer_StartCleanup(t *testing.T) {
	b := newTestBalancer([]config.InstanceConfig{makeInstance("inst1", 5)})
	ctx, cancel := context.WithCancel(context.Background())
	b.StartCleanup(ctx)
	time.Sleep(10 * time.Millisecond)
	cancel()
}

// Test: ActiveSessions count
func TestBalancer_ActiveSessions(t *testing.T) {
	b := newTestBalancer([]config.InstanceConfig{makeInstance("inst1", 5)})
	if b.ActiveSessions() != 0 {
		t.Error("expected 0 sessions initially")
	}
	b.BindSession("s1", "inst1")
	b.BindSession("s2", "inst1")
	if b.ActiveSessions() != 2 {
		t.Errorf("expected 2 sessions, got %d", b.ActiveSessions())
	}
	b.ClearSession("s1")
	if b.ActiveSessions() != 1 {
		t.Errorf("expected 1 session after clear, got %d", b.ActiveSessions())
	}
}

// Test: Cooldown instance is skipped during selection
func TestSelectInstance_CooldownSkipped(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("cool", 5),
		makeInstance("warm", 5),
	}
	b := newTestBalancer(instances)

	// Put "cool" in cooldown
	b.ReportResult("cool", 429, 1000, 30*time.Second)

	result, err := b.SelectInstance("", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name != "warm" {
		t.Errorf("expected warm (cool is in cooldown), got %s", result.Instance.Name)
	}
	result.Release()
}

// Test: Disabled instance is skipped
func TestSelectInstance_DisabledSkipped(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("forbidden", 5),
		makeInstance("ok", 5),
	}
	b := newTestBalancer(instances)

	// Disable "forbidden" with a 403
	b.ReportResult("forbidden", 403, 1000, 0)

	result, err := b.SelectInstance("", map[string]bool{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Instance.Name != "ok" {
		t.Errorf("expected ok (forbidden is disabled), got %s", result.Instance.Name)
	}
	result.Release()
}

// Test: ReportResult updates health state
func TestReportResult_UpdatesHealth(t *testing.T) {
	b := newTestBalancer([]config.InstanceConfig{makeInstance("inst1", 5)})

	b.ReportResult("inst1", 200, 1000, 0)
	h := b.GetHealth("inst1")
	if h == nil {
		t.Fatal("expected health tracker for inst1")
	}
	if h.LatencyEMA() == 0 {
		t.Error("expected latency to be recorded")
	}

	// Report error and check error rate increases
	b.ReportResult("inst1", 500, 1000, 0)
	if h.ErrorRate() == 0 {
		t.Error("expected error rate to increase after error")
	}
}

// Test: UpdateInstances cleans up health for removed instances
func TestBalancer_UpdateInstances_CleansHealth(t *testing.T) {
	instances := []config.InstanceConfig{
		makeInstance("inst-a", 5),
		makeInstance("inst-b", 5),
	}
	b := newTestBalancer(instances)

	// Verify both have health
	if b.GetHealth("inst-a") == nil {
		t.Fatal("expected health for inst-a")
	}
	if b.GetHealth("inst-b") == nil {
		t.Fatal("expected health for inst-b")
	}

	// Update to only inst-b
	b.UpdateInstances([]config.InstanceConfig{makeInstance("inst-b", 5)})

	if b.GetHealth("inst-a") != nil {
		t.Error("expected health for inst-a to be cleaned up")
	}
	if b.GetHealth("inst-b") == nil {
		t.Error("expected health for inst-b to still exist")
	}
}
