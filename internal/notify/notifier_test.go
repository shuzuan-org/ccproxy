package notify

import (
	"context"
	"testing"
)

func TestNoopNotifier(t *testing.T) {
	t.Parallel()
	n := &NoopNotifier{}
	if err := n.Notify(context.Background(), Event{AccountName: "test", Type: EventAccountDisabled}); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestGlobalSingleton(t *testing.T) {
	// Do NOT use t.Parallel() — modifies global state.
	orig := Global()
	defer SetGlobal(orig)

	mock := &mockNotifier{}
	SetGlobal(mock)
	if Global() != mock {
		t.Fatal("SetGlobal did not update Global()")
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
	events []Event
}

func (m *mockNotifier) Notify(_ context.Context, e Event) error {
	m.events = append(m.events, e)
	return nil
}
