package loadbalancer

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/notify"
)

// mockNotifier captures events for assertion (thread-safe).
type mockNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (m *mockNotifier) Notify(_ context.Context, e notify.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}

func (m *mockNotifier) Events() []notify.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]notify.Event, len(m.events))
	copy(cp, m.events)
	return cp
}

// withMockNotifier sets up a global NotifierRegistry with the mock as the admin
// notifier (receives all events). Restores the previous registry via t.Cleanup.
// Tests using this helper must NOT call t.Parallel() because they mutate shared
// global state.
func withMockNotifier(t *testing.T) *mockNotifier {
	t.Helper()
	mock := &mockNotifier{}
	orig := notify.GlobalRegistry()
	reg := notify.NewRegistry(func(string) string { return "" })
	// Register mock as admin so it receives all events (admin notifier gets everything).
	reg.Set("admin", mock)
	notify.SetGlobalRegistry(reg)
	t.Cleanup(func() { notify.SetGlobalRegistry(orig) })
	return mock
}

func TestDisable_NotifiesAccountDisabled(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct1")
	h.Disable("consecutive_401")
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(events))
	}
	if events[0].Type != notify.EventAccountDisabled {
		t.Errorf("expected EventAccountDisabled, got %s", events[0].Type)
	}
	if events[0].AccountName != "acct1" {
		t.Errorf("expected account acct1, got %s", events[0].AccountName)
	}
}

func TestDisable_NotifiesAccountBanned(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct2")
	h.Disable(PlatformBanReasonForbidden)
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(events))
	}
	if events[0].Type != notify.EventAccountBanned {
		t.Errorf("expected EventAccountBanned, got %s", events[0].Type)
	}
}

func TestRecordError_429True_NotifiesRateLimited(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct3")
	headers := http.Header{
		"Anthropic-Ratelimit-Unified-5h-Reset": []string{time.Now().Add(time.Minute).Format(time.RFC3339)},
	}
	h.RecordError(context.Background(), 429, 0, headers)
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(events))
	}
	if events[0].Type != notify.EventRateLimited {
		t.Errorf("expected EventRateLimited, got %s", events[0].Type)
	}
}

func TestRecordError_529_NotifiesOverloaded(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct4")
	h.RecordError(context.Background(), 529, 0, nil)
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(events))
	}
	if events[0].Type != notify.EventOverloaded {
		t.Errorf("expected EventOverloaded, got %s", events[0].Type)
	}
}

func TestRecordTimeout_ThresholdReached_NotifiesTimeoutCooldown(t *testing.T) {
	mock := withMockNotifier(t)
	h := NewAccountHealth("acct5")
	ctx := context.Background()
	for i := 0; i < timeoutThreshold; i++ {
		h.RecordTimeout(ctx)
	}
	events := mock.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 notification after threshold, got %d", len(events))
	}
	if events[0].Type != notify.EventTimeoutCooldown {
		t.Errorf("expected EventTimeoutCooldown, got %s", events[0].Type)
	}
}

