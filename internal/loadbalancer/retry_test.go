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

// Test 3: ClassifyError(429) with no headers → RetryThenFailover (fake 429).
// A bare 429 has no rate-limit reset headers, so it is treated as a transient
// fake 429 and retried on the same account before failover.
func TestClassifyError_429(t *testing.T) {
	if got := ClassifyError(429); got != RetryThenFailover {
		t.Errorf("expected RetryThenFailover for headerless 429, got %v", got)
	}
}

// Test 4: ClassifyError(503) → RetryThenFailover
func TestClassifyError_503(t *testing.T) {
	if got := ClassifyError(503); got != RetryThenFailover {
		t.Errorf("expected RetryThenFailover for 503, got %v", got)
	}
}

// Test 5: ClassifyError(529) → RetryThenFailover (short retry before cooldown).
func TestClassifyError_529(t *testing.T) {
	if got := ClassifyError(529); got != RetryThenFailover {
		t.Errorf("expected RetryThenFailover for 529, got %v", got)
	}
}

// Test 5b: ClassifyErrorWithHeaders distinguishes fake vs true 429.
func TestClassifyErrorWithHeaders(t *testing.T) {
	trueHeaders := http.Header{"Anthropic-Ratelimit-Unified-5h-Reset": []string{"1700000000"}}

	cases := []struct {
		name    string
		status  int
		headers http.Header
		want    FailureAction
	}{
		{"fake 429 nil headers", 429, nil, RetryThenFailover},
		{"fake 429 empty headers", 429, http.Header{}, RetryThenFailover},
		{"true 429 with reset", 429, trueHeaders, FailoverImmediate},
		{"529", 529, nil, RetryThenFailover},
		{"401", 401, nil, FailoverImmediate},
		{"503", 503, nil, RetryThenFailover},
		{"400", 400, nil, ReturnToClient},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyErrorWithHeaders(tc.status, tc.headers); got != tc.want {
				t.Errorf("ClassifyErrorWithHeaders(%d): expected %v, got %v", tc.status, tc.want, got)
			}
		})
	}
}

// Test 5c: retryBudget per status code.
func TestRetryBudget(t *testing.T) {
	trueHeaders := http.Header{"Anthropic-Ratelimit-Unified-7d-Reset": []string{"1700000000"}}
	cases := []struct {
		name    string
		status  int
		headers http.Header
		want    int
	}{
		{"fake 429", 429, nil, 3},
		{"true 429", 429, trueHeaders, maxSameAccountRetries},
		{"529", 529, nil, 2},
		{"503", 503, nil, maxSameAccountRetries},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryBudget(tc.status, tc.headers); got != tc.want {
				t.Errorf("retryBudget(%d): expected %d, got %d", tc.status, tc.want, got)
			}
		})
	}
}

// Test 5d: retryDelayFor per status code and attempt.
func TestRetryDelayFor(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		attempt int
		want    time.Duration
	}{
		{"fake 429 attempt0", 429, 0, 500 * time.Millisecond},
		{"fake 429 attempt1", 429, 1, 1 * time.Second},
		{"529 attempt0", 529, 0, 1500 * time.Millisecond},
		{"503 falls back to RetryDelay", 503, 0, 300 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := retryDelayFor(tc.status, nil, tc.attempt); got != tc.want {
				t.Errorf("retryDelayFor(%d, %d): expected %v, got %v", tc.status, tc.attempt, tc.want, got)
			}
		})
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

func makeRetryAccount(name string) config.AccountConfig {
	return config.AccountConfig{
		ID:             name + "-id",
		Name:           name,
		MaxConcurrency: 5,
		BaseURL:        "https://api.anthropic.com",
		RequestTimeout: 300,
		Enabled:        true,
	}
}

func newRetryBalancer(names ...string) *Balancer {
	accounts := make([]config.AccountConfig, len(names))
	for i, n := range names {
		accounts[i] = makeRetryAccount(n)
	}
	return NewBalancer(accounts, NewConcurrencyTracker())
}

func okResponse() *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{}}
}

var noCallbacks = RetryCallbacks{}

// Test 7: Success on first try
func TestExecuteWithRetry_SuccessFirstTry(t *testing.T) {
	b := newRetryBalancer("inst1")

	calls := 0
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		calls++
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
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
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		calls++
		if calls < 2 {
			return &http.Response{StatusCode: 503, Header: http.Header{}}, 503, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
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
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		calls++
		return &http.Response{StatusCode: 400, Header: http.Header{}}, 400, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
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

// Test 10: 429 → failovers to different account
func TestExecuteWithRetry_429Failover(t *testing.T) {
	b := newRetryBalancer("inst1", "inst2")

	callsByAccount := make(map[string]int)
	failCount := 0
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		callsByAccount[acct.Name]++
		// First call always returns 429, second call succeeds
		failCount++
		if failCount == 1 {
			return &http.Response{StatusCode: 429, Header: http.Header{}}, 429, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200 after failover, got %d", result.StatusCode)
	}
	// Both accounts should have been tried (one failed, one succeeded)
	totalCalls := 0
	for _, c := range callsByAccount {
		totalCalls += c
	}
	if totalCalls < 2 {
		t.Errorf("expected at least 2 total calls (failover), got %d", totalCalls)
	}
}

// Test 10b: fake 429 then success → same-account retry succeeds WITHOUT cooling
// down the account (mid-retry attempts skip ReportResult).
func TestExecuteWithRetry_Fake429RetriesNoCooldown(t *testing.T) {
	b := newRetryBalancer("inst1")

	calls := 0
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		calls++
		if calls == 1 {
			// Fake 429: no rate-limit reset headers.
			return &http.Response{StatusCode: 429, Header: http.Header{}}, 429, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.StatusCode != 200 {
		t.Errorf("expected 200 after same-account retry, got %d", result.StatusCode)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls (1 fake 429 + 1 success), got %d", calls)
	}
	// The account must NOT be in cooldown — the retry succeeded before exhaustion.
	if h := b.GetHealth("inst1-id"); h != nil && !h.IsAvailable() {
		t.Errorf("account should remain available (not cooled down) after a retried fake 429")
	}
}

// Test 10c: 529 retried once then still 529 → fails over and cools down the account.
func TestExecuteWithRetry_529RetryThenCooldown(t *testing.T) {
	b := newRetryBalancer("inst1")

	calls := 0
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		calls++
		return &http.Response{StatusCode: 529, Header: http.Header{}}, 529, nil
	}

	_, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
	if err == nil {
		t.Fatal("expected error when single account stays 529")
	}
	// 529 budget is 1 retry → 2 attempts on the one account.
	if calls != 2 {
		t.Errorf("expected 2 calls (1 retry for 529), got %d", calls)
	}
	// After exhausting retries the account must be cooled down.
	if h := b.GetHealth("inst1-id"); h == nil || h.IsAvailable() {
		t.Errorf("account should be in cooldown after exhausted 529 retries")
	}
}

// Test 11: All accounts fail → returns error
func TestExecuteWithRetry_AllFail(t *testing.T) {
	// Use accounts with capacity=1 and always 429 → all get excluded quickly
	accounts := []config.AccountConfig{
		makeRetryAccount("inst1"),
		makeRetryAccount("inst2"),
	}
	b := NewBalancer(accounts, NewConcurrencyTracker())

	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		return &http.Response{StatusCode: 429, Header: http.Header{}}, 429, nil
	}

	_, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
	if err == nil {
		t.Fatal("expected error when all accounts fail")
	}
}

// Test 12: Context cancelled → returns context error
func TestExecuteWithRetry_ContextCancelled(t *testing.T) {
	b := newRetryBalancer("inst1")

	ctx, cancel := context.WithCancel(context.Background())

	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		cancel() // cancel context during request
		return &http.Response{StatusCode: 503, Header: http.Header{}}, 503, nil
	}

	_, err := ExecuteWithRetry(ctx, b, "", nil, false, noCallbacks, fn)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// Test: network error (non-nil error) triggers failover
func TestExecuteWithRetry_NetworkError(t *testing.T) {
	b := newRetryBalancer("inst1", "inst2")

	callsByAccount := make(map[string]int)
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		callsByAccount[acct.Name]++
		if acct.Name == "inst1" {
			// Network error → statusCode=0, action=FailoverImmediate (default)
			return nil, 0, errors.New("connection refused")
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, noCallbacks, fn)
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
		OnTokenRefreshNeeded: func(ctx context.Context, accountName string) {
			refreshCalled = true
		},
	}

	callCount := 0
	fn := func(acct config.AccountConfig, reqID string) (*http.Response, int, error) {
		callCount++
		if callCount == 1 {
			return &http.Response{StatusCode: 401, Header: http.Header{}}, 401, nil
		}
		return okResponse(), 200, nil
	}

	result, err := ExecuteWithRetry(context.Background(), b, "", nil, false, callbacks, fn)
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
