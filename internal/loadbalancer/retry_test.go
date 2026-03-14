package loadbalancer

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

// Test 1: ClassifyError(400) → ReturnToClient
func TestClassifyError_400(t *testing.T) {
	if got := ClassifyError(400); got != ReturnToClient {
		t.Errorf("expected ReturnToClient for 400, got %v", got)
	}
}

// Test 2: ClassifyError(401) → FailoverImmediate
func TestClassifyError_401(t *testing.T) {
	if got := ClassifyError(401); got != FailoverImmediate {
		t.Errorf("expected FailoverImmediate for 401, got %v", got)
	}
}

// Test 3: ClassifyError(429) → FailoverImmediate
func TestClassifyError_429(t *testing.T) {
	if got := ClassifyError(429); got != FailoverImmediate {
		t.Errorf("expected FailoverImmediate for 429, got %v", got)
	}
}

// Test 4: ClassifyError(503) → RetryThenFailover
func TestClassifyError_503(t *testing.T) {
	if got := ClassifyError(503); got != RetryThenFailover {
		t.Errorf("expected RetryThenFailover for 503, got %v", got)
	}
}

// Test 5: ClassifyError(529) → FailoverImmediate
func TestClassifyError_529(t *testing.T) {
	if got := ClassifyError(529); got != FailoverImmediate {
		t.Errorf("expected FailoverImmediate for 529, got %v", got)
	}
}

// Test 6: RetryDelay exponential backoff with cap
func TestRetryDelay(t *testing.T) {
	cases := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 300 * time.Millisecond},
		{1, 600 * time.Millisecond},
		{2, 1200 * time.Millisecond},
		{3, 2400 * time.Millisecond},
		{4, 3000 * time.Millisecond}, // capped at retryMaxDelay
	}
	for _, tc := range cases {
		got := RetryDelay(tc.attempt)
		if got != tc.expected {
			t.Errorf("RetryDelay(%d): expected %v, got %v", tc.attempt, tc.expected, got)
		}
	}
}

// helpers for retry tests

func makeRetryInstance(name string) config.InstanceConfig {
	return config.InstanceConfig{
		Name:           name,
		MaxConcurrency: 5,
		BaseURL:        "https://api.anthropic.com",
		RequestTimeout: 300,
		Enabled:        true,
	}
}

func newRetryBalancer(names ...string) *Balancer {
	instances := make([]config.InstanceConfig, len(names))
	for i, n := range names {
		instances[i] = makeRetryInstance(n)
	}
	return NewBalancer(instances, NewConcurrencyTracker())
}

func okResponse() *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}}
}

var noCallbacks = RetryCallbacks{}

// Test 7: Success on first try
func TestExecuteWithRetry_SuccessFirstTry(t *testing.T) {
	b := newRetryBalancer("inst1")

	calls := 0
	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		calls++
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

// Test 8: 503 then success → retries and succeeds
func TestExecuteWithRetry_503ThenSuccess(t *testing.T) {
	b := newRetryBalancer("inst1")

	calls := 0
	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		calls++
		if calls < 2 {
			return &http.Response{StatusCode: 503, Header: http.Header{}}, 503, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}
	if calls < 2 {
		t.Errorf("expected at least 2 calls, got %d", calls)
	}
}

// Test 9: 400 → returns immediately without retry
func TestExecuteWithRetry_400NoRetry(t *testing.T) {
	b := newRetryBalancer("inst1")

	calls := 0
	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		calls++
		return &http.Response{StatusCode: 400, Header: http.Header{}}, 400, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", result.StatusCode)
	}
	if calls != 1 {
		t.Errorf("expected exactly 1 call (no retry), got %d", calls)
	}
}

// Test 10: 429 → failovers to different instance
func TestExecuteWithRetry_429Failover(t *testing.T) {
	b := newRetryBalancer("inst1", "inst2")

	callsByInstance := make(map[string]int)
	failCount := 0
	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		callsByInstance[inst.Name]++
		// First call always returns 429, second call succeeds
		failCount++
		if failCount == 1 {
			return &http.Response{StatusCode: 429, Header: http.Header{}}, 429, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200 after failover, got %d", result.StatusCode)
	}
	// Both instances should have been tried (one failed, one succeeded)
	totalCalls := 0
	for _, c := range callsByInstance {
		totalCalls += c
	}
	if totalCalls < 2 {
		t.Errorf("expected at least 2 total calls (failover), got %d", totalCalls)
	}
}

// Test 11: All instances fail → returns error
func TestExecuteWithRetry_AllFail(t *testing.T) {
	// Use instances with capacity=1 and always 429 → all get excluded quickly
	instances := []config.InstanceConfig{
		makeRetryInstance("inst1"),
		makeRetryInstance("inst2"),
	}
	b := NewBalancer(instances, NewConcurrencyTracker())

	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{}}, 429, nil
	}

	_, err := ExecuteWithRetry(context.Background(), b, "", false, noCallbacks, fn)
	if err == nil {
		t.Fatal("expected error when all instances fail")
	}
}

// Test 12: Context cancelled → returns context error
func TestExecuteWithRetry_ContextCancelled(t *testing.T) {
	b := newRetryBalancer("inst1")

	ctx, cancel := context.WithCancel(context.Background())

	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		cancel() // cancel context during request
		return &http.Response{StatusCode: 503, Header: http.Header{}}, 503, nil
	}

	_, err := ExecuteWithRetry(ctx, b, "", false, noCallbacks, fn)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// Test: network error (non-nil error) triggers failover
func TestExecuteWithRetry_NetworkError(t *testing.T) {
	b := newRetryBalancer("inst1", "inst2")

	callsByInstance := make(map[string]int)
	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		callsByInstance[inst.Name]++
		if inst.Name == "inst1" {
			// Network error → statusCode=0, action=FailoverImmediate (default)
			return nil, 0, errors.New("connection refused")
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200 after failover, got %d", result.StatusCode)
	}
}

// Test: ClassifyError covers remaining cases
func TestClassifyError_Various(t *testing.T) {
	cases := []struct {
		code   int
		action FailureAction
	}{
		{403, FailoverImmediate},
		{500, RetryThenFailover},
		{502, RetryThenFailover},
		{504, RetryThenFailover},
		{404, ReturnToClient},   // 4xx not in special list
		{422, ReturnToClient},   // generic 4xx
		{200, FailoverImmediate}, // non-error codes fall to default
	}
	for _, tc := range cases {
		got := ClassifyError(tc.code)
		if got != tc.action {
			t.Errorf("ClassifyError(%d): expected %v, got %v", tc.code, tc.action, got)
		}
	}
}

// Test: RetryCallbacks.OnTokenRefreshNeeded is called on 401
func TestExecuteWithRetry_401TriggersRefresh(t *testing.T) {
	b := newRetryBalancer("inst1", "inst2")

	refreshCalled := false
	callbacks := RetryCallbacks{
		OnTokenRefreshNeeded: func(ctx context.Context, instanceName string) {
			refreshCalled = true
		},
	}

	callCount := 0
	fn := func(inst config.InstanceConfig, reqID string) (*http.Response, int, error) {
		callCount++
		if callCount == 1 {
			return &http.Response{StatusCode: 401, Header: http.Header{}}, 401, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", false, callbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200, got %d", result.StatusCode)
	}
	if !refreshCalled {
		t.Error("expected OnTokenRefreshNeeded to be called on 401")
	}
}
