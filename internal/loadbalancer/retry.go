package loadbalancer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/observe"
)

// FailureAction determines how to handle an upstream error.
type FailureAction int

const (
	ReturnToClient    FailureAction = iota // 400: return directly
	FailoverImmediate                       // 401,403,429,529: switch account
	RetryThenFailover                       // 500-504: retry same, then switch
)

const (
	maxAccountSwitches     = 3
	maxSameAccountRetries = 3
	retryBaseDelay         = 300 * time.Millisecond
	retryMaxDelay          = 3 * time.Second
	maxRetryElapsed        = 10 * time.Second
)

// ClassifyError returns the appropriate action for an upstream HTTP status code
// without response-header context. Equivalent to ClassifyErrorWithHeaders with
// nil headers: a 429 is treated as a true (quota) 429 and fails over immediately.
func ClassifyError(statusCode int) FailureAction {
	return ClassifyErrorWithHeaders(statusCode, nil)
}

// ClassifyErrorWithHeaders returns the appropriate action for an upstream status
// code, using response headers to distinguish a fake 429 (transient overload,
// no rate-limit reset headers) from a true 429 (quota exhausted, carries reset
// headers). A fake 429 is worth retrying on the same account; a true 429 is not.
func ClassifyErrorWithHeaders(statusCode int, headers http.Header) FailureAction {
	switch {
	case statusCode == 400:
		return ReturnToClient
	case statusCode == 429:
		// True 429 (quota) carries reset headers — failover immediately.
		// Fake 429 (transient) has no reset headers — retry same account first.
		if hasResetHeaders(headers) {
			return FailoverImmediate
		}
		return RetryThenFailover
	case statusCode == 529:
		// Upstream overload — allow a short retry before failover/cooldown.
		return RetryThenFailover
	case statusCode == 401 || statusCode == 403:
		return FailoverImmediate
	case statusCode >= 500 && statusCode <= 504:
		return RetryThenFailover
	default:
		if statusCode >= 400 && statusCode < 500 {
			return ReturnToClient
		}
		return FailoverImmediate
	}
}

// hasResetHeaders reports whether the response carries Anthropic rate-limit reset
// headers, which mark a true (quota) 429 as opposed to a transient fake 429.
func hasResetHeaders(headers http.Header) bool {
	if headers == nil {
		return false
	}
	return headers.Get("anthropic-ratelimit-unified-5h-reset") != "" ||
		headers.Get("anthropic-ratelimit-unified-7d-reset") != ""
}

// retryBudget returns the max same-account attempts for a status code before
// failing over (counting the first attempt). The mid-loop counter starts at 1
// on the first failure, so a budget of N allows N-1 extra retries. Fake 429 gets
// 3 (2 retries), 529 gets 2 (1 retry), 500-504 keep the default.
func retryBudget(statusCode int, headers http.Header) int {
	switch {
	case statusCode == 429 && !hasResetHeaders(headers):
		return 3
	case statusCode == 529:
		return 2
	default:
		return maxSameAccountRetries
	}
}

// retryDelayFor returns the backoff delay before a same-account retry for the
// given status code and 0-based attempt. Fake 429 uses 500ms→1s, 529 uses 1.5s,
// and everything else falls back to the exponential RetryDelay.
func retryDelayFor(statusCode int, headers http.Header, attempt int) time.Duration {
	switch {
	case statusCode == 429 && !hasResetHeaders(headers):
		if attempt <= 0 {
			return 500 * time.Millisecond
		}
		return 1 * time.Second
	case statusCode == 529:
		return 1500 * time.Millisecond
	default:
		return RetryDelay(attempt)
	}
}

// RetryDelay calculates exponential backoff delay for the given attempt (0-based).
func RetryDelay(attempt int) time.Duration {
	delay := retryBaseDelay * time.Duration(1<<uint(attempt))
	if delay > retryMaxDelay {
		delay = retryMaxDelay
	}
	return delay
}

// RequestFunc is called for each attempt. Returns response, HTTP status code, and error.
// The response should only be read/used if error is nil.
type RequestFunc func(account config.AccountConfig, requestID string) (*http.Response, int, error)

// RetryCallbacks holds optional callbacks for retry events.
type RetryCallbacks struct {
	OnTokenRefreshNeeded func(ctx context.Context, accountID string)
}

// RetryResult contains the result of ExecuteWithRetry.
type RetryResult struct {
	Response       *http.Response
	StatusCode     int
	AccountID      string
	AccountName    string
	Body           []byte // for error responses that should be forwarded
	AccountsTried  []string
	Retries        int
	Failovers      int
}

// ExecuteWithRetry runs the request function with retry and failover logic.
// scope (optional, may be nil) restricts candidate accounts by owner. Errors
// of type ErrScopeEmpty are returned to the caller without retrying.
func ExecuteWithRetry(
	ctx context.Context,
	balancer *Balancer,
	sessionKey string,
	scope *config.ResolvedScope,
	isStream bool,
	callbacks RetryCallbacks,
	requestFn RequestFunc,
) (*RetryResult, error) {
	startTime := time.Now()
	failedAccounts := make(map[string]bool)
	switchCount := 0
	var accountsTried []string
	retries := 0
	failovers := 0
	total529s := 0 // cross-account 529 counter for storm detection

	for switchCount <= maxAccountSwitches {
		// Check total elapsed time
		if time.Since(startTime) > maxRetryElapsed {
			observe.Logger(ctx).Warn("retry elapsed time exceeded",
				"elapsed", time.Since(startTime).String(),
				"max", maxRetryElapsed.String(),
				"switches", switchCount,
			)
			return nil, fmt.Errorf("retry elapsed time exceeded (%s)", maxRetryElapsed)
		}

		// Select account
		result, err := balancer.SelectAccount(ctx, sessionKey, scope, failedAccounts, isStream)
		if err != nil {
			observe.Logger(ctx).Warn("no account available",
				"error", err.Error(),
				"failed_count", len(failedAccounts),
				"switches", switchCount,
			)
			return nil, fmt.Errorf("select account: %w", err)
		}

		accountID := result.Account.ID
		accountName := result.Account.Name
		accountsTried = append(accountsTried, accountName)
		sameAccountRetries := 0
		switched := false
		observe.Logger(ctx).Debug("selected account", "account", accountName, "switch", switchCount)

		// The inner loop terminates via explicit branches: ReturnToClient returns,
		// FailoverImmediate and budget-exhausted RetryThenFailover set `switched`
		// and break. The per-status retryBudget is the single source of truth for
		// how many same-account attempts are allowed — do not add a second bound
		// on sameAccountRetries here, or it will silently override the budget.
		for {
			// Check context cancellation
			if ctx.Err() != nil {
				result.Release()
				return nil, ctx.Err()
			}

			// Check total elapsed time
			if time.Since(startTime) > maxRetryElapsed {
				result.Release()
				return nil, fmt.Errorf("retry elapsed time exceeded (%s)", maxRetryElapsed)
			}

			attemptStart := time.Now()
			resp, statusCode, err := requestFn(result.Account, result.RequestID)
			attemptLatency := time.Since(attemptStart).Microseconds()

			if err == nil && statusCode >= 200 && statusCode < 400 {
				// Success — report with response headers for budget tracking.
				var headers http.Header
				if resp != nil {
					headers = resp.Header
				}
				balancer.ReportResult(ctx, accountID, statusCode, attemptLatency, 0, headers)
				balancer.BindSession(sessionKey, accountID)
				result.Release()
				return &RetryResult{
					Response:       resp,
					StatusCode:     statusCode,
					AccountID:      accountID,
					AccountName:    accountName,
					AccountsTried:  accountsTried,
					Retries:        retries,
					Failovers:      failovers,
				}, nil
			}

			// Extract response headers for budget tracking and 429 classification.
			var respHeaders http.Header
			if resp != nil {
				respHeaders = resp.Header
			}

			action := ClassifyErrorWithHeaders(statusCode, respHeaders)
			retryAfter := parseRetryAfterHeader(resp)

			switch action {
			case ReturnToClient:
				observe.Logger(ctx).Debug("retry: returning to client",
					"account", accountName,
					"status", statusCode,
				)
				result.Release()
				return &RetryResult{
					Response:       resp,
					StatusCode:     statusCode,
					AccountID:      accountID,
					AccountName:    accountName,
					AccountsTried:  accountsTried,
					Retries:        retries,
					Failovers:      failovers,
				}, nil

			case FailoverImmediate:
				// Special handling per status code. Note: 529 and fake 429 are
				// classified as RetryThenFailover, so only true 429 (with reset
				// headers), 401, and 403 reach here.
				switch statusCode {
				case 429:
					observe.Global.Accounts429.Add(1)
					observe.Global.Account(accountID).Errors429.Add(1)
					observe.Logger(ctx).Warn("failover: rate limited",
						"account", accountName,
						"has_reset_headers", hasResetHeaders(respHeaders),
						"switch", switchCount+1,
					)
				case 401:
					if callbacks.OnTokenRefreshNeeded != nil {
						callbacks.OnTokenRefreshNeeded(ctx, accountID)
					}
				}

				observe.Logger(ctx).Warn("failover immediate",
					"account", accountName,
					"status", statusCode,
					"switch", switchCount+1,
					"retry_after", retryAfter.String(),
				)
				balancer.ReportResult(ctx, accountID, statusCode, attemptLatency, retryAfter, respHeaders)

				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				result.Release()
				failedAccounts[accountID] = true
				balancer.ClearSession(sessionKey)
				switchCount++
				failovers++
				switched = true
				observe.Global.FailoversTotal.Add(1)

			case RetryThenFailover:
				budget := retryBudget(statusCode, respHeaders)
				sameAccountRetries++
				retries++
				observe.Global.RetriesTotal.Add(1)
				observe.Logger(ctx).Warn("retry on same account",
					"account", accountName,
					"status", statusCode,
					"attempt", sameAccountRetries,
					"max_attempts", budget,
				)
				if sameAccountRetries >= budget {
					// Exhausted same-account retries — report (triggers cooldown
					// + budget tracking) and fail over to the next account. Record
					// the per-status observe counters here, since fake 429 / 529
					// reach failover through this path rather than FailoverImmediate.
					switch statusCode {
					case 429:
						observe.Global.Accounts429.Add(1)
						observe.Global.Account(accountID).Errors429.Add(1)
					case 529:
						observe.Global.Accounts529.Add(1)
						observe.Global.Account(accountID).Errors529.Add(1)
						total529s++
					}
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
					balancer.ReportResult(ctx, accountID, statusCode, attemptLatency, retryAfter, respHeaders)
					if statusCode == 529 && total529s >= 2 {
						// Multiple accounts overloaded — system-wide, stop retrying.
						observe.Logger(ctx).Warn("consecutive 529s across accounts, returning to client",
							"account", accountName, "count", total529s)
						result.Release()
						return &RetryResult{
							Response:       resp,
							StatusCode:     529,
							AccountID:      accountID,
							AccountName:    accountName,
							AccountsTried:  accountsTried,
							Retries:        retries,
							Failovers:      failovers,
						}, nil
					}
					result.Release()
					failedAccounts[accountID] = true
					balancer.ClearSession(sessionKey)
					switchCount++
					failovers++
					switched = true
					observe.Global.FailoversTotal.Add(1)
					break
				}
				// Mid-retry attempt: deliberately skip ReportResult so the account
				// is NOT cooled down while we still intend to retry it. A fake 429
				// or transient 529 that succeeds on retry leaves health untouched.
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				delay := retryDelayFor(statusCode, respHeaders, sameAccountRetries-1)
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					result.Release()
					return nil, ctx.Err()
				case <-timer.C:
				}
			}

			if switched {
				break
			}
		}
	}

	observe.Logger(ctx).Error("max account switches exceeded",
		"max", maxAccountSwitches,
		"elapsed", time.Since(startTime).String(),
	)
	return nil, fmt.Errorf("max account switches (%d) exceeded", maxAccountSwitches)
}

// parseRetryAfterHeader extracts Retry-After as a duration from an HTTP response.
func parseRetryAfterHeader(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	val := resp.Header.Get("Retry-After")
	if val == "" {
		return 0
	}
	// Try seconds first (most common for APIs).
	var seconds int
	if _, err := fmt.Sscanf(val, "%d", &seconds); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return 0
}
