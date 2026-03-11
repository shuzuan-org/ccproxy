package loadbalancer

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

// FailureAction determines how to handle an upstream error.
type FailureAction int

const (
	ReturnToClient    FailureAction = iota // 400: return directly
	FailoverImmediate                       // 401,403,429,529: switch instance
	RetryThenFailover                       // 500-504: retry same, then switch
)

const (
	maxRetryAttempts       = 5
	maxAccountSwitches     = 3
	maxSameInstanceRetries = 3
	retryBaseDelay         = 300 * time.Millisecond
	retryMaxDelay          = 3 * time.Second
	maxRetryElapsed        = 10 * time.Second
)

// ClassifyError returns the appropriate action for an upstream HTTP status code.
func ClassifyError(statusCode int) FailureAction {
	switch {
	case statusCode == 400:
		return ReturnToClient
	case statusCode == 401 || statusCode == 403:
		return FailoverImmediate
	case statusCode == 429:
		return FailoverImmediate
	case statusCode == 529:
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

// RetryDelay calculates exponential backoff delay for the given attempt (0-based).
func RetryDelay(attempt int) time.Duration {
	delay := retryBaseDelay * time.Duration(math.Pow(2, float64(attempt)))
	if delay > retryMaxDelay {
		delay = retryMaxDelay
	}
	return delay
}

// RequestFunc is called for each attempt. Returns response, HTTP status code, and error.
// The response should only be read/used if error is nil.
type RequestFunc func(instance config.InstanceConfig, requestID string) (*http.Response, int, error)

// RetryResult contains the result of ExecuteWithRetry.
type RetryResult struct {
	Response     *http.Response
	StatusCode   int
	InstanceName string
	Body         []byte // for error responses that should be forwarded
}

// ExecuteWithRetry runs the request function with retry and failover logic.
func ExecuteWithRetry(
	ctx context.Context,
	balancer *Balancer,
	sessionKey string,
	requestFn RequestFunc,
) (*RetryResult, error) {
	startTime := time.Now()
	failedInstances := make(map[string]bool)
	switchCount := 0

	for switchCount <= maxAccountSwitches {
		// Check total elapsed time
		if time.Since(startTime) > maxRetryElapsed {
			return nil, fmt.Errorf("retry elapsed time exceeded (%s)", maxRetryElapsed)
		}

		// Select instance
		result, err := balancer.SelectInstance(sessionKey, failedInstances)
		if err != nil {
			return nil, fmt.Errorf("select instance: %w", err)
		}

		instanceName := result.Instance.Name
		sameInstanceRetries := 0
		switched := false

		for sameInstanceRetries < maxSameInstanceRetries {
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
			resp, statusCode, err := requestFn(result.Instance, result.RequestID)
			attemptLatency := time.Since(attemptStart).Microseconds()

			if err == nil && statusCode >= 200 && statusCode < 400 {
				// Success — health is reported by handler after response is consumed.
				balancer.BindSession(sessionKey, instanceName)
				result.Release()
				return &RetryResult{
					Response:     resp,
					StatusCode:   statusCode,
					InstanceName: instanceName,
				}, nil
			}

			action := ClassifyError(statusCode)
			retryAfter := parseRetryAfterHeader(resp)

			switch action {
			case ReturnToClient:
				result.Release()
				return &RetryResult{
					Response:     resp,
					StatusCode:   statusCode,
					InstanceName: instanceName,
				}, nil

			case FailoverImmediate:
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				balancer.ReportResult(instanceName, statusCode, attemptLatency, retryAfter)
				result.Release()
				failedInstances[instanceName] = true
				balancer.ClearSession(sessionKey)
				switchCount++
				switched = true

			case RetryThenFailover:
				sameInstanceRetries++
				if sameInstanceRetries >= maxSameInstanceRetries {
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
					balancer.ReportResult(instanceName, statusCode, attemptLatency, retryAfter)
					result.Release()
					failedInstances[instanceName] = true
					balancer.ClearSession(sessionKey)
					switchCount++
					switched = true
					break
				}
				// Report the failed attempt (but don't trigger failover yet).
				balancer.ReportResult(instanceName, statusCode, attemptLatency, retryAfter)
				// Close previous response body before retrying.
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				// Exponential backoff before retry
				delay := RetryDelay(sameInstanceRetries - 1)
				select {
				case <-ctx.Done():
					result.Release()
					return nil, ctx.Err()
				case <-time.After(delay):
				}
			}

			if switched {
				break
			}
		}
	}

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
