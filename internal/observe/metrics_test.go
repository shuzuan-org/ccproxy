package observe

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMetrics_Snapshot(t *testing.T) {
	t.Parallel()

	m := &Metrics{}
	m.RequestsTotal.Store(10)
	m.RequestsThrottled.Store(2)
	m.RequestsQueued.Store(1)
	m.RequestsSuccess.Store(7)
	m.RequestsError.Store(3)
	m.RetriesTotal.Store(4)
	m.FailoversTotal.Store(1)
	m.Accounts429.Store(5)
	m.Accounts529.Store(2)

	snap := m.Snapshot()

	expected := map[string]int64{
		"requests_total":     10,
		"requests_throttled": 2,
		"requests_queued":    1,
		"requests_success":   7,
		"requests_error":     3,
		"retries_total":      4,
		"failovers_total":    1,
		"accounts_429":      5,
		"accounts_529":      2,
	}

	for k, want := range expected {
		if got := snap[k]; got != want {
			t.Errorf("snap[%q] = %d, want %d", k, got, want)
		}
	}
}

func TestMetrics_ConcurrentAddSnapshot(t *testing.T) {
	t.Parallel()

	m := &Metrics{}
	const goroutines = 100
	const iterations = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines + 1)

	// Writers
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				m.RequestsTotal.Add(1)
				m.RequestsSuccess.Add(1)
				m.RetriesTotal.Add(1)
			}
		}()
	}

	// Reader (concurrent with writers)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			snap := m.Snapshot()
			// Values should be non-negative
			for k, v := range snap {
				if v < 0 {
					t.Errorf("snap[%q] = %d, want >= 0", k, v)
				}
			}
		}
	}()

	wg.Wait()

	// Final values should equal goroutines * iterations
	want := int64(goroutines * iterations)
	if got := m.RequestsTotal.Load(); got != want {
		t.Errorf("RequestsTotal = %d, want %d", got, want)
	}
}

func TestAccountMetrics(t *testing.T) {
	t.Parallel()
	m := &Metrics{}

	am1 := m.Account("acct-1")
	if am1 == nil {
		t.Fatal("Account returned nil")
	}

	// Same pointer on repeated access
	am2 := m.Account("acct-1")
	if am1 != am2 {
		t.Fatal("Account returned different pointer for same name")
	}

	// Different account returns different pointer
	am3 := m.Account("acct-2")
	if am1 == am3 {
		t.Fatal("Different accounts returned same pointer")
	}

	am1.RequestsTotal.Add(5)
	am1.RequestsSuccess.Add(3)
	am1.RequestsError.Add(2)
	am1.Errors429.Add(1)
	am1.Errors529.Add(1)

	if am1.RequestsTotal.Load() != 5 {
		t.Fatalf("expected 5, got %d", am1.RequestsTotal.Load())
	}
}

func TestMetrics_StartPeriodicLog(t *testing.T) {
	t.Parallel()

	m := &Metrics{}
	m.RequestsTotal.Store(42)

	ctx, cancel := context.WithCancel(context.Background())

	// Start with very short interval
	m.StartPeriodicLog(ctx, 10*time.Millisecond, nil, nil)

	// Let it tick a couple times
	time.Sleep(50 * time.Millisecond)

	// Cancel should stop the goroutine
	cancel()
	time.Sleep(20 * time.Millisecond)

	// No panic or race = pass
}

// safeBuf is a goroutine-safe wrapper around bytes.Buffer for use in tests.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestStartPeriodicLogWithState(t *testing.T) {
	t.Parallel()

	var buf safeBuf
	handler := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	logger := slog.New(handler)

	m := &Metrics{}
	m.RequestsTotal.Store(100)
	m.RequestsSuccess.Store(95)
	m.Account("acct-1").RequestsTotal.Store(60)
	m.Account("acct-2").RequestsTotal.Store(40)

	provider := &mockStateProvider{
		states: map[string]AccountState{
			"acct-1": {Health: "healthy", Concurrency: 2, MaxConcurrency: 5, BudgetState: "normal"},
			"acct-2": {Health: "cooldown", Concurrency: 0, MaxConcurrency: 5, BudgetState: "sticky_only"},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.StartPeriodicLog(ctx, 50*time.Millisecond, provider, logger)
	time.Sleep(80 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	output := buf.String()
	if !strings.Contains(output, "metrics summary") {
		t.Errorf("missing 'metrics summary' in output:\n%s", output)
	}
	if !strings.Contains(output, "requests_per_min") {
		t.Errorf("missing 'requests_per_min' in output:\n%s", output)
	}
	if !strings.Contains(output, "metrics account") {
		t.Errorf("missing 'metrics account' in output:\n%s", output)
	}
}

type mockStateProvider struct {
	states map[string]AccountState
}

func (m *mockStateProvider) AccountStates() map[string]AccountState {
	return m.states
}
