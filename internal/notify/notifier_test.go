package notify

import (
	"context"
	"sync"
	"testing"
)

func TestNoopNotifier(t *testing.T) {
	t.Parallel()
	n := &NoopNotifier{}
	if err := n.Notify(context.Background(), Event{AccountName: "test", Type: EventAccountDisabled}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestGlobalRegistry(t *testing.T) {
	// Do NOT use t.Parallel() — modifies global state.
	orig := GlobalRegistry()
	defer SetGlobalRegistry(orig)

	reg := NewRegistry(func(string) string { return "" })
	SetGlobalRegistry(reg)
	if GlobalRegistry() != reg {
		t.Fatal("SetGlobalRegistry did not update GlobalRegistry()")
	}
}

func TestNotifyAllGlobal_NilRegistry(t *testing.T) {
	// Do NOT use t.Parallel() — modifies global state.
	orig := GlobalRegistry()
	defer SetGlobalRegistry(orig)

	SetGlobalRegistry(nil)
	// Should not panic.
	NotifyAllGlobal(context.Background(), Event{AccountName: "test", Type: EventAccountDisabled})
}

func TestNotifierRegistry_AdminReceivesAll(t *testing.T) {
	t.Parallel()
	mock := &mockNotifier{}
	reg := NewRegistry(func(string) string { return "alice" })
	reg.Set("admin", mock)

	reg.NotifyAll(context.Background(), Event{AccountName: "acct1", Type: EventRateLimited})
	reg.NotifyAll(context.Background(), Event{AccountName: "acct1", Type: EventAccountDisabled})

	if len(mock.events) != 2 {
		t.Errorf("admin should receive all events, got %d", len(mock.events))
	}
}

func TestNotifierRegistry_UserReceivesOnlyOwnDisabled(t *testing.T) {
	t.Parallel()
	adminMock := &mockNotifier{}
	aliceMock := &mockNotifier{}
	bobMock := &mockNotifier{}

	reg := NewRegistry(func(accountName string) string {
		if accountName == "acct-alice" {
			return "alice"
		}
		return "bob"
	})
	reg.Set("admin", adminMock)
	reg.Set("alice", aliceMock)
	reg.Set("bob", bobMock)

	// Alice's account gets disabled — alice should get it, bob should not.
	reg.NotifyAll(context.Background(), Event{AccountName: "acct-alice", Type: EventAccountDisabled})
	// Alice's account gets rate limited — only admin gets it (anomaly, not disabled).
	reg.NotifyAll(context.Background(), Event{AccountName: "acct-alice", Type: EventRateLimited})
	// Bob's account gets banned.
	reg.NotifyAll(context.Background(), Event{AccountName: "acct-bob", Type: EventAccountBanned})

	if len(adminMock.events) != 3 {
		t.Errorf("admin should receive 3 events, got %d", len(adminMock.events))
	}
	if len(aliceMock.events) != 1 {
		t.Errorf("alice should receive 1 event (disabled), got %d", len(aliceMock.events))
	}
	if aliceMock.events[0].Type != EventAccountDisabled {
		t.Errorf("alice should receive EventAccountDisabled, got %s", aliceMock.events[0].Type)
	}
	if len(bobMock.events) != 1 {
		t.Errorf("bob should receive 1 event (banned), got %d", len(bobMock.events))
	}
}

func TestEventTypeCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		e    EventType
		want EventCategory
	}{
		{EventAccountDisabled, CategoryDisabled},
		{EventAccountBanned, CategoryDisabled},
		{EventRateLimited, CategoryAnomaly},
		{EventOverloaded, CategoryAnomaly},
		{EventTimeoutCooldown, CategoryAnomaly},
		{EventBudgetBlocked, CategoryAnomaly},
	}
	for _, tc := range cases {
		if got := tc.e.Category(); got != tc.want {
			t.Errorf("%s: want %v, got %v", tc.e, tc.want, got)
		}
	}
}

// mockNotifier is shared across test files in this package.
type mockNotifier struct {
	mu     sync.Mutex
	events []Event
}

func (m *mockNotifier) Notify(_ context.Context, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	return nil
}
