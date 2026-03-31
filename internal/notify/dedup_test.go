package notify

import (
	"testing"
	"time"
)

func TestDedupBasic(t *testing.T) {
	t.Parallel()
	d := NewDedup(5 * time.Minute)

	if !d.Allow("acct1", EventRateLimited) {
		t.Fatal("first call should be allowed")
	}
	if d.Allow("acct1", EventRateLimited) {
		t.Fatal("second call within TTL should be denied")
	}
	if !d.Allow("acct1", EventOverloaded) {
		t.Fatal("different event type should be allowed")
	}
	if !d.Allow("acct2", EventRateLimited) {
		t.Fatal("different account should be allowed")
	}
}

func TestDedupTTLExpiry(t *testing.T) {
	t.Parallel()
	d := NewDedup(40 * time.Millisecond)

	if !d.Allow("acct", EventOverloaded) {
		t.Fatal("first call should be allowed")
	}
	time.Sleep(50 * time.Millisecond)
	if !d.Allow("acct", EventOverloaded) {
		t.Fatal("call after TTL should be allowed")
	}
}

func TestDedupConcurrent(t *testing.T) {
	t.Parallel()
	d := NewDedup(time.Minute)
	allowed := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		go func() { allowed <- d.Allow("acct", EventBudgetBlocked) }()
	}
	count := 0
	for i := 0; i < 100; i++ {
		if <-allowed {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 allowed, got %d", count)
	}
}
