package loadbalancer

// NOTE: These tests do NOT call t.Parallel() because withMockNotifier replaces
// the global Notifier singleton. Parallel execution would cause races between
// tests that share that global state.
//
// time.Sleep(20ms) is intentional: checkStateChange fires notify inside a
// goroutine (required because it is called with bc.mu held), so we must yield
// to let the goroutine run before asserting on captured events.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/notify"
)

func TestBudgetCheckStateChange_BlockedNotifies(t *testing.T) {
	mock := withMockNotifier(t) // reuse helper from health_notify_test.go
	bc := NewBudgetController("budget-acct")

	// Drive state into Blocked by injecting headers with high utilization.
	// Note: http.Header literal keys are NOT canonicalized, so we must use
	// the exact canonical form that http.Header.Get expects (5h not 5H).
	headers := http.Header{
		"Anthropic-Ratelimit-Unified-5h-Utilization": []string{"0.98"},
		"Anthropic-Ratelimit-Unified-5h-Status":      []string{"allowed"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       []string{time.Now().Add(time.Hour).Format(time.RFC3339)},
	}
	bc.UpdateFromHeaders(context.Background(), headers)

	// Give goroutine time to fire
	time.Sleep(20 * time.Millisecond)

	found := false
	for _, e := range mock.Events() {
		if e.Type == notify.EventBudgetBlocked && e.AccountName == "budget-acct" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected EventBudgetBlocked notification, got %v", mock.Events())
	}
}

func TestBudgetCheckStateChange_NormalDoesNotNotify(t *testing.T) {
	mock := withMockNotifier(t)
	bc := NewBudgetController("budget-acct2")

	headers := http.Header{
		"Anthropic-Ratelimit-Unified-5h-Utilization": []string{"0.50"},
		"Anthropic-Ratelimit-Unified-5h-Status":      []string{"allowed"},
		"Anthropic-Ratelimit-Unified-5h-Reset":       []string{time.Now().Add(time.Hour).Format(time.RFC3339)},
	}
	bc.UpdateFromHeaders(context.Background(), headers)
	time.Sleep(20 * time.Millisecond)

	for _, e := range mock.Events() {
		if e.Type == notify.EventBudgetBlocked {
			t.Errorf("unexpected EventBudgetBlocked for normal utilization")
		}
	}
}
