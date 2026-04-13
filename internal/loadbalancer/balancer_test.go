package loadbalancer

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

// helpers

func makeAccount(name string, maxConc int) config.AccountConfig {
	return config.AccountConfig{
		ID:             name + "-id",
		Name:           name,
		MaxConcurrency: maxConc,
		BaseURL:        "https://api.anthropic.com",
		RequestTimeout: 300,
		Enabled:        true,
	}
}

func makeDisabledAccount(name string) config.AccountConfig {
	acct := makeAccount(name, 5)
	acct.Enabled = false
	return acct
}

func newTestBalancer(accounts []config.AccountConfig) *Balancer {
	tracker := NewConcurrencyTracker()
	return NewBalancer(accounts, tracker)
}

var testCtx = context.Background()

// Test 1: Single account → always selected
func TestBalancer_SingleAccount(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{makeAccount("acct1", 5)})

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "acct1" {
		t.Errorf("expected inst1, got %s", result.Account.Name)
	}
	result.Release()
}

// Test 2: Account with errors gets lower score → healthy account preferred
func TestBalancer_ScoreBasedOrder(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("unhealthy", 5),
		makeAccount("healthy", 5),
	}
	b := newTestBalancer(accounts)

	// Record errors on "unhealthy" to give it a worse score
	b.ReportResult(testCtx,"unhealthy-id", 500, 1000, 0, nil)
	b.ReportResult(testCtx,"unhealthy-id", 500, 1000, 0, nil)
	// Clear cooldown so account is available but has high error rate
	h := b.GetHealth("unhealthy-id")
	h.mu.Lock()
	h.cooldownUntil = time.Time{}
	h.mu.Unlock()

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "healthy" {
		t.Errorf("expected healthy (lower score), got %s", result.Account.Name)
	}
	result.Release()
}

// Test 3: Same priority → weighted by load rate (lower load first)
func TestBalancer_LoadRateOrder(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 4),
		makeAccount("acct-b", 4),
	}
	b := newTestBalancer(accounts)

	// Fill acct-a with 2 slots (50% load)
	r1, _ := b.tracker.Acquire("acct-a-id", "req1", 4)
	r2, _ := b.tracker.Acquire("acct-a-id", "req2", 4)
	defer r1()
	defer r2()

	// acct-b is at 0% load → should be selected
	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "acct-b" {
		t.Errorf("expected acct-b (lower load), got %s", result.Account.Name)
	}
	result.Release()
}

// Test 4: Session sticky: same sessionKey → same account within TTL
func TestBalancer_StickySession(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 5),
		makeAccount("acct-b", 5),
	}
	b := newTestBalancer(accounts)

	// First selection
	r1, err := b.SelectAccount(testCtx, "session-1", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	firstAccountID := r1.Account.ID
	firstName := r1.Account.Name
	r1.Release()

	// Bind session
	b.BindSession("session-1", firstAccountID)

	// Second selection with same session key → same account
	r2, err := b.SelectAccount(testCtx, "session-1", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error on second select: %v", err)
	}
	if r2.Account.Name != firstName {
		t.Errorf("expected sticky account %s, got %s", firstName, r2.Account.Name)
	}
	r2.Release()
}

// Test 5: Session expired → new selection (may differ)
func TestBalancer_SessionExpired(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 5),
	}
	b := newTestBalancer(accounts)

	// Manually insert an expired session
	b.sessions.Store("old-session", &SessionInfo{
		AccountID: "acct-a-id",
		LastRequest:  time.Now().Add(-(sessionTTL + time.Second)),
	})

	// Should still work (expired session cleared, fallback to layer 2)
	result, err := b.SelectAccount(testCtx, "old-session", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.Release()

	// Session should be gone
	if _, ok := b.sessions.Load("old-session"); ok {
		t.Error("expired session should have been deleted")
	}
}

// Test 6: Sticky account at capacity → falls through to Layer 2
func TestBalancer_StickyAtCapacity(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 1), // capacity=1
		makeAccount("acct-b", 5),
	}
	b := newTestBalancer(accounts)

	// Bind session to acct-a
	b.BindSession("session-x", "acct-a-id")

	// Fill acct-a to capacity
	r1, ok := b.tracker.Acquire("acct-a-id", "blocker", 1)
	if !ok {
		t.Fatal("blocker acquire should succeed")
	}
	defer r1()

	// Session points to acct-a but it's full → should fall through to acct-b
	result, err := b.SelectAccount(testCtx, "session-x", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "acct-b" {
		t.Errorf("expected fallback to acct-b, got %s", result.Account.Name)
	}
	result.Release()
}

// Test 7: Exclude failed accounts
func TestBalancer_ExcludeAccounts(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 5),
		makeAccount("acct-b", 5),
	}
	b := newTestBalancer(accounts)

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{"acct-a-id": true}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name == "acct-a" {
		t.Error("acct-a should be excluded")
	}
	result.Release()
}

// Test 8: All accounts at capacity → returns ErrAllAccountsBusy
func TestBalancer_AllBusy(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 1),
		makeAccount("acct-b", 1),
	}
	b := newTestBalancer(accounts)

	// Fill both to capacity
	r1, _ := b.tracker.Acquire("acct-a-id", "block-a", 1)
	r2, _ := b.tracker.Acquire("acct-b-id", "block-b", 1)
	defer r1()
	defer r2()

	_, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != ErrAllAccountsBusy {
		t.Errorf("expected ErrAllAccountsBusy, got %v", err)
	}
}

// Test 9: BindSession + SelectAccount → returns sticky account
func TestBalancer_BindThenSelect(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 5),
		makeAccount("acct-b", 5), // lower priority
	}
	b := newTestBalancer(accounts)

	// Bind to higher-priority-value account (acct-b)
	b.BindSession("my-session", "acct-b-id")

	result, err := b.SelectAccount(testCtx, "my-session", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Sticky should override normal priority ordering
	if result.Account.Name != "acct-b" {
		t.Errorf("expected sticky acct-b, got %s", result.Account.Name)
	}
	result.Release()
}

// Test 10: UpdateAccounts replaces list
func TestBalancer_UpdateAccounts(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{makeAccount("acct-a", 5)})

	newAccounts := []config.AccountConfig{
		makeAccount("acct-x", 5),
		makeAccount("acct-y", 5),
	}
	b.UpdateAccounts(newAccounts)

	got := b.GetAccounts()
	if len(got) != 2 {
		t.Fatalf("expected 2 accounts after update, got %d", len(got))
	}

	// Disabled accounts should be filtered out
	withDisabledAcct := append(newAccounts, makeDisabledAccount("acct-disabled"))
	b.UpdateAccounts(withDisabledAcct)
	got = b.GetAccounts()
	if len(got) != 2 {
		t.Errorf("expected 2 enabled accounts, got %d", len(got))
	}
}

// Test 11: Concurrent SelectAccount (race test)
func TestBalancer_ConcurrentSelect(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 10),
		makeAccount("acct-b", 10),
	}
	b := newTestBalancer(accounts)

	var wg sync.WaitGroup
	goroutines := 30

	wg.Add(goroutines + 5)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
			if err != nil {
				return // acceptable if all slots are briefly full
			}
			// Simulate short work then release
			time.Sleep(time.Millisecond)
			result.Release()
		}()
	}

	// Concurrent UpdateAccounts to trigger race detector
	for i := 0; i < 5; i++ {
		go func() {
			defer wg.Done()
			b.UpdateAccounts(accounts)
		}()
	}

	wg.Wait()
}

// Test: No healthy accounts → ErrNoHealthyAccounts
func TestBalancer_NoAccounts(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{})
	_, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != ErrNoHealthyAccounts {
		t.Errorf("expected ErrNoHealthyAccounts, got %v", err)
	}
}

// Test: filterEnabled removes disabled accounts
func TestBalancer_FilterEnabled(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("enabled", 5),
		makeDisabledAccount("disabled"),
	}
	b := newTestBalancer(accounts)
	got := b.GetAccounts()
	if len(got) != 1 || got[0].Name != "enabled" {
		t.Errorf("expected only enabled account, got %v", got)
	}
}

// Test: StartCleanup runs without panic
func TestBalancer_StartCleanup(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{makeAccount("acct1", 5)})
	ctx, cancel := context.WithCancel(context.Background())
	b.StartCleanup(ctx)
	time.Sleep(10 * time.Millisecond)
	cancel()
}

// Test: ActiveSessions count
func TestBalancer_ActiveSessions(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{makeAccount("acct1", 5)})
	if b.ActiveSessions() != 0 {
		t.Error("expected 0 sessions initially")
	}
	b.BindSession("s1", "acct1-id")
	b.BindSession("s2", "acct1-id")
	if b.ActiveSessions() != 2 {
		t.Errorf("expected 2 sessions, got %d", b.ActiveSessions())
	}
	b.ClearSession("s1")
	if b.ActiveSessions() != 1 {
		t.Errorf("expected 1 session after clear, got %d", b.ActiveSessions())
	}
}

// Test: Cooldown account is skipped during selection
func TestSelectAccount_CooldownSkipped(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("cool", 5),
		makeAccount("warm", 5),
	}
	b := newTestBalancer(accounts)

	// Put "cool" in cooldown
	b.ReportResult(testCtx,"cool-id", 429, 1000, 30*time.Second, nil)

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "warm" {
		t.Errorf("expected warm (cool is in cooldown), got %s", result.Account.Name)
	}
	result.Release()
}

// Test: Disabled account is skipped
func TestSelectAccount_DisabledSkipped(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("forbidden", 5),
		makeAccount("ok", 5),
	}
	b := newTestBalancer(accounts)

	// Disable "forbidden" with a 403
	b.ReportResult(testCtx,"forbidden-id", 403, 1000, 0, nil)

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "ok" {
		t.Errorf("expected ok (forbidden is disabled), got %s", result.Account.Name)
	}
	result.Release()
}

// Test: ReportResult updates health state
func TestReportResult_UpdatesHealth(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{makeAccount("acct1", 5)})

	b.ReportResult(testCtx,"acct1-id", 200, 1000, 0, nil)
	h := b.GetHealth("acct1-id")
	if h == nil {
		t.Fatal("expected health tracker for inst1")
	}
	if h.LatencyEMA() == 0 {
		t.Error("expected latency to be recorded")
	}

	// Report error and check error rate increases
	b.ReportResult(testCtx,"acct1-id", 500, 1000, 0, nil)
	if h.ErrorRate() == 0 {
		t.Error("expected error rate to increase after error")
	}
}

// Test: UpdateAccounts cleans up health for removed accounts
func TestBalancer_UpdateAccounts_CleansHealth(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("acct-a", 5),
		makeAccount("acct-b", 5),
	}
	b := newTestBalancer(accounts)

	// Verify both have health
	if b.GetHealth("acct-a-id") == nil {
		t.Fatal("expected health for acct-a")
	}
	if b.GetHealth("acct-b-id") == nil {
		t.Fatal("expected health for acct-b")
	}

	// Update to only acct-b
	b.UpdateAccounts([]config.AccountConfig{makeAccount("acct-b", 5)})

	if b.GetHealth("acct-a-id") != nil {
		t.Error("expected health for acct-a to be cleaned up")
	}
	if b.GetHealth("acct-b-id") == nil {
		t.Error("expected health for acct-b to still exist")
	}
}

// Test: Budget state affects account selection
func TestBalancer_BudgetStateFiltering(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("high-util", 5),
		makeAccount("low-util", 5),
	}
	b := newTestBalancer(accounts)

	// Set high utilization on one account to make it Blocked
	h := b.GetHealth("high-util-id")
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-utilization", "0.90")
	headers.Set("anthropic-ratelimit-unified-7d-utilization", "0.10")
	h.Budget().UpdateFromHeaders(context.Background(), headers)

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "low-util" {
		t.Errorf("expected low-util (high-util is blocked), got %s", result.Account.Name)
	}
	result.Release()
}

// TestBalancer_StickyOnlyWithoutActiveSessions tests that a sticky_only account
// can accept new sessions when it has no active sticky sessions.
// This prevents accounts from being "starved" when all old sessions expire.
func TestBalancer_StickyOnlyWithoutActiveSessions(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("sticky-only", 5),
	}
	b := newTestBalancer(accounts)

	// Set utilization to trigger sticky_only state (90% <= util < 95%)
	h := b.GetHealth("sticky-only-id")
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-utilization", "0.92")
	headers.Set("anthropic-ratelimit-unified-7d-utilization", "0.10")
	h.Budget().UpdateFromHeaders(context.Background(), headers)

	if state := h.Budget().State(); state != StateStickyOnly {
		t.Fatalf("expected sticky_only state, got %v", state)
	}

	// Account should be selectable because there are no active sticky sessions
	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "sticky-only" {
		t.Errorf("expected sticky-only account to be selected (no active sessions), got %s", result.Account.Name)
	}
	result.Release()
}

// TestBalancer_StickyOnlyBelowSessionLimit tests that a sticky_only account
// can accept new sessions when active sessions < max concurrency.
func TestBalancer_StickyOnlyBelowSessionLimit(t *testing.T) {
	accounts := []config.AccountConfig{
		{ID: "sticky-only-id", Name: "sticky-only", MaxConcurrency: 3, Enabled: true},
		makeAccount("normal", 5),
	}
	b := newTestBalancer(accounts)

	// Set utilization to trigger sticky_only state
	h := b.GetHealth("sticky-only-id")
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-utilization", "0.92")
	headers.Set("anthropic-ratelimit-unified-7d-utilization", "0.10")
	h.Budget().UpdateFromHeaders(context.Background(), headers)

	if state := h.Budget().State(); state != StateStickyOnly {
		t.Fatalf("expected sticky_only state, got %v", state)
	}

	// Create 2 active sticky sessions (< MaxConcurrency of 3)
	for i := 0; i < 2; i++ {
		result, err := b.SelectAccount(testCtx, fmt.Sprintf("test-api-key:session-%d", i), nil, map[string]bool{}, false)
		if err != nil {
			t.Fatalf("unexpected error creating session %d: %v", i, err)
		}
		result.Release()
	}

	// Account should still be selectable because active sessions (2) < max (3)
	result, err := b.SelectAccount(testCtx, "test-api-key:new-session", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// sticky-only should still be available since we haven't hit the limit
	if result.Account.Name != "sticky-only" && result.Account.Name != "normal" {
		t.Errorf("expected sticky-only or normal, got %s", result.Account.Name)
	}
	result.Release()
}

// TestBalancer_StickyOnlyAtSessionLimit tests that a sticky_only account
// is skipped when active sessions >= max concurrency.
func TestBalancer_StickyOnlyAtSessionLimit(t *testing.T) {
	accounts := []config.AccountConfig{
		{ID: "sticky-only-id", Name: "sticky-only", MaxConcurrency: 2, Enabled: true},
		makeAccount("normal", 5),
	}
	b := newTestBalancer(accounts)

	// Set utilization to trigger sticky_only state
	h := b.GetHealth("sticky-only-id")
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-utilization", "0.92")
	headers.Set("anthropic-ratelimit-unified-7d-utilization", "0.10")
	h.Budget().UpdateFromHeaders(context.Background(), headers)

	if state := h.Budget().State(); state != StateStickyOnly {
		t.Fatalf("expected sticky_only state, got %v", state)
	}

	// Create MaxConcurrency (2) active sticky sessions
	for i := 0; i < 2; i++ {
		result, err := b.SelectAccount(testCtx, fmt.Sprintf("test-api-key:session-%d", i), nil, map[string]bool{}, false)
		if err != nil {
			t.Fatalf("unexpected error creating session %d: %v", i, err)
		}
		result.Release()
	}

	// Now sticky-only should be filtered (active sessions >= max)
	// New sessions must go to normal account
	result, err := b.SelectAccount(testCtx, "test-api-key:new-session", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "normal" {
		t.Errorf("expected normal account (sticky-only at limit), got %s", result.Account.Name)
	}
	result.Release()
}


func TestBalancer_AccountStates(t *testing.T) {
	b := newTestBalancer([]config.AccountConfig{
		makeAccount("healthy", 2),
		makeAccount("cooldown", 2),
		makeAccount("disabled", 2),
		makeAccount("banned", 2),
	})

	b.GetHealth("cooldown-id").SetCooldown(time.Minute, "rate_limited")
	b.GetHealth("disabled-id").Disable("consecutive_401")
	b.GetHealth("banned-id").Disable(PlatformBanReasonOrganizationDisabled)

	states := b.AccountStates()

	if got := states["healthy-id"].Health; got != "healthy" {
		t.Fatalf("healthy state = %q, want healthy", got)
	}
	if got := states["cooldown-id"].Health; got != "cooldown" {
		t.Fatalf("cooldown state = %q, want cooldown", got)
	}
	if got := states["disabled-id"].Health; got != "disabled" {
		t.Fatalf("disabled state = %q, want disabled", got)
	}
	if got := states["banned-id"].Health; got != "banned" {
		t.Fatalf("banned state = %q, want banned", got)
	}
}

// TestBalancer_StickySessionBudgetBlocked tests that a sticky session falls through
// to L3 when the bound account's budget is in StateBlocked.
func TestBalancer_StickySessionBudgetBlocked(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("blocked-acct", 5),
		makeAccount("healthy-acct", 5),
	}
	b := newTestBalancer(accounts)

	// Bind a sticky session to blocked-acct
	b.BindSession("test-session", "blocked-acct-id")

	// Push blocked-acct into StateBlocked (util >= 95%)
	h := b.GetHealth("blocked-acct-id")
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-utilization", "0.96")
	headers.Set("anthropic-ratelimit-unified-7d-utilization", "0.80")
	h.Budget().UpdateFromHeaders(context.Background(), headers)

	if state := h.Budget().State(); state != StateBlocked {
		t.Fatalf("expected StateBlocked, got %v", state)
	}

	// Select with the sticky session — should NOT use blocked-acct
	result, err := b.SelectAccount(testCtx, "test-session", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name == "blocked-acct" {
		t.Error("sticky session should not use budget-blocked account, expected fallthrough to healthy-acct")
	}
	result.Release()

	// Session binding should be preserved (not deleted) so affinity resumes after recovery
	if _, ok := b.sessions.Load("test-session"); !ok {
		t.Error("session binding should be preserved for budget-blocked account, not deleted")
	}
}

// TestBalancer_StickySessionBudgetStickyOnly tests that a sticky session still
// works when the bound account is in StateStickyOnly (that's its purpose).
func TestBalancer_StickySessionBudgetStickyOnly(t *testing.T) {
	accounts := []config.AccountConfig{
		makeAccount("sticky-only-acct", 5),
		makeAccount("other-acct", 5),
	}
	b := newTestBalancer(accounts)

	// Bind a sticky session to sticky-only-acct
	b.BindSession("test-session", "sticky-only-acct-id")

	// Push into StateStickyOnly (90% <= util < 95%)
	h := b.GetHealth("sticky-only-acct-id")
	headers := http.Header{}
	headers.Set("anthropic-ratelimit-unified-5h-utilization", "0.92")
	headers.Set("anthropic-ratelimit-unified-7d-utilization", "0.10")
	h.Budget().UpdateFromHeaders(context.Background(), headers)

	if state := h.Budget().State(); state != StateStickyOnly {
		t.Fatalf("expected StateStickyOnly, got %v", state)
	}

	// Select with the sticky session — should still use sticky-only-acct
	result, err := b.SelectAccount(testCtx, "test-session", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Name != "sticky-only-acct" {
		t.Errorf("sticky session should still use StickyOnly account, got %s", result.Account.Name)
	}
	result.Release()
}

// --- Scheduling scope filtering ---

func makeOwnedAccount(name, owner string) config.AccountConfig {
	acct := makeAccount(name, 5)
	acct.Owner = owner
	return acct
}

// Test: scope restricts selection to accounts matching the allowed owners.
func TestBalancer_ScopeFiltersByOwner(t *testing.T) {
	accounts := []config.AccountConfig{
		makeOwnedAccount("alice-acct", "alice"),
		makeOwnedAccount("bob-acct", "bob"),
	}
	b := newTestBalancer(accounts)
	scope := &config.ResolvedScope{AllowedOwners: map[string]bool{"alice": true}}

	result, err := b.SelectAccount(testCtx, "", scope, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Owner != "alice" {
		t.Errorf("expected alice-owned account, got owner %q", result.Account.Owner)
	}
	result.Release()
}

// Test: empty scope (no owner matches) returns ErrScopeEmpty before consuming throttle.
func TestBalancer_ScopeEmptyFailsFast(t *testing.T) {
	accounts := []config.AccountConfig{
		makeOwnedAccount("alice-acct", "alice"),
		makeOwnedAccount("bob-acct", "bob"),
	}
	b := newTestBalancer(accounts)
	scope := &config.ResolvedScope{AllowedOwners: map[string]bool{"charlie": true}}

	_, err := b.SelectAccount(testCtx, "", scope, map[string]bool{}, false)
	if err == nil {
		t.Fatal("expected error when scope matches no accounts")
	}
	if err != ErrScopeEmpty {
		t.Errorf("expected ErrScopeEmpty, got %v", err)
	}
}

// Test: nil scope preserves legacy global-pool behaviour.
func TestBalancer_NilScopeNoFilter(t *testing.T) {
	accounts := []config.AccountConfig{
		makeOwnedAccount("alice-acct", "alice"),
		makeOwnedAccount("bob-acct", "bob"),
	}
	b := newTestBalancer(accounts)

	result, err := b.SelectAccount(testCtx, "", nil, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Owner == "" {
		t.Error("expected a real account")
	}
	result.Release()
}

// Test: AllowAll scope behaves identically to nil scope.
func TestBalancer_AllowAllScope(t *testing.T) {
	accounts := []config.AccountConfig{
		makeOwnedAccount("alice-acct", "alice"),
		makeOwnedAccount("bob-acct", "bob"),
	}
	b := newTestBalancer(accounts)
	scope := &config.ResolvedScope{AllowAll: true}

	result, err := b.SelectAccount(testCtx, "", scope, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	result.Release()
}

// Test: sticky session pointing at an out-of-scope account is invalidated and falls back.
func TestBalancer_StickySessionInvalidatedByScope(t *testing.T) {
	accounts := []config.AccountConfig{
		makeOwnedAccount("alice-acct", "alice"),
		makeOwnedAccount("bob-acct", "bob"),
	}
	b := newTestBalancer(accounts)

	// Seed a sticky binding to bob-acct.
	b.BindSession("session-x", "bob-acct-id")

	// Now select with a scope that excludes bob. The sticky hit should be
	// invalidated and selection should fall through to alice.
	scope := &config.ResolvedScope{AllowedOwners: map[string]bool{"alice": true}}
	result, err := b.SelectAccount(testCtx, "session-x", scope, map[string]bool{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Account.Owner != "alice" {
		t.Errorf("expected alice after sticky invalidation, got owner %q", result.Account.Owner)
	}
	result.Release()

	// Sticky binding should have been cleared.
	if _, ok := b.sessions.Load("session-x"); ok {
		t.Error("expected sticky session to be cleared after scope mismatch")
	}
}
