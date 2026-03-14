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
	FailoverImmediate                       // 401,403,429,529: switch instance
	RetryThenFailover                       // 500-504: retry same, then switch
)

const (
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
	case statusCode == 401 || statusCode == 403 || statusCode == 429 || statusCode == 529:
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
	delay := retryBaseDelay * time.Duration(1<<uint(attempt))
	if delay > retryMaxDelay {
		delay = retryMaxDelay
	}
	return delay
}

// RequestFunc is called for each attempt. Returns response, HTTP status code, and error.
// The response should only be read/used if error is nil.
type RequestFunc func(instance config.InstanceConfig, requestID string) (*http.Response, int, error)

// RetryCallbacks holds optional callbacks for retry events.
type RetryCallbacks struct {
	OnTokenRefreshNeeded func(ctx context.Context, instanceName string)
}

// RetryResult contains the result of ExecuteWithRetry.
type RetryResult struct {
	Response       *http.Response
	StatusCode     int
	InstanceName   string
	Body           []byte // for error responses that should be forwarded
	InstancesTried []string
	Retries        int
	Failovers      int
}

// ExecuteWithRetry runs the request function with retry and failover logic.
func ExecuteWithRetry(
	ctx context.Context,
	balancer *Balancer,
	sessionKey string,
	isStream bool,
	callbacks RetryCallbacks,
	requestFn RequestFunc,
) (*RetryResult, error) {
	startTime := time.Now()
	failedInstances := make(map[string]bool)
	switchCount := 0
	var instancesTried []string
	retries := 0
	failovers := 0

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

		// Select instance
		result, err := balancer.SelectInstance(ctx, sessionKey, failedInstances, isStream)
		if err != nil {
			observe.Logger(ctx).Warn("no instance available",
				"error", err.Error(),
				"failed_count", len(failedInstances),
				"switches", switchCount,
			)
			return nil, fmt.Errorf("select instance: %w", err)
		}

		instanceName := result.Instance.Name
		instancesTried = append(instancesTried, instanceName)
		sameInstanceRetries := 0
		switched := false
		observe.Logger(ctx).Debug("selected instance", "instance", instanceName, "switch", switchCount)

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
				// Success — report with response headers for budget tracking.
				var headers http.Header
				if resp != nil {
					headers = resp.Header
				}
				balancer.ReportResult(ctx, instanceName, statusCode, attemptLatency, 0, headers)
				balancer.BindSession(sessionKey, instanceName)
				result.Release()
				return &RetryResult{
					Response:       resp,
					StatusCode:     statusCode,
					InstanceName:   instanceName,
					InstancesTried: instancesTried,
					Retries:        retries,
					Failovers:      failovers,
				}, nil
			}

			action := ClassifyError(statusCode)
			retryAfter := parseRetryAfterHeader(resp)

			// Extract response headers for budget tracking
			var respHeaders http.Header
			if resp != nil {
				respHeaders = resp.Header
			}

			switch action {
			case ReturnToClient:
				result.Release()
				return &RetryResult{
					Response:       resp,
					StatusCode:     statusCode,
					InstanceName:   instanceName,
					InstancesTried: instancesTried,
					Retries:        retries,
					Failovers:      failovers,
				}, nil

			case FailoverImmediate:
				// Special handling per status code
				switch statusCode {
				case 429:
					observe.Global.Instances429.Add(1)
					observe.Global.Instance(instanceName).Errors429.Add(1)
					hasResetHeaders := respHeaders != nil &&
						(respHeaders.Get("anthropic-ratelimit-unified-5h-reset") != "" ||
							respHeaders.Get("anthropic-ratelimit-unified-7d-reset") != "")
					observe.Logger(ctx).Warn("failover: rate limited",
						"instance", instanceName,
						"has_reset_headers", hasResetHeaders,
						"switch", switchCount+1,
					)
				case 529:
					observe.Global.Instances529.Add(1)
					observe.Global.Instance(instanceName).Errors529.Add(1)
					// Check consecutive 529 across instances
					h := balancer.GetHealth(instanceName)
					balancer.ReportResult(ctx, instanceName, statusCode, attemptLatency, retryAfter, respHeaders)
					if h != nil && h.Consecutive529() >= 2 {
						// Multiple instances returning 529 — stop retrying
						observe.Logger(ctx).Warn("consecutive 529s across instances, returning to client",
							"instance", instanceName, "count", h.Consecutive529())
						result.Release()
						return &RetryResult{
							Response:       resp,
							StatusCode:     529,
							InstanceName:   instanceName,
							InstancesTried: instancesTried,
							Retries:        retries,
							Failovers:      failovers,
						}, nil
					}
				case 401:
					if callbacks.OnTokenRefreshNeeded != nil {
						callbacks.OnTokenRefreshNeeded(ctx, instanceName)
					}
				}

				if statusCode != 529 { // 529 already reported above
					observe.Logger(ctx).Warn("failover immediate",
						"instance", instanceName,
						"status", statusCode,
						"switch", switchCount+1,
						"retry_after", retryAfter.String(),
					)
					balancer.ReportResult(ctx, instanceName, statusCode, attemptLatency, retryAfter, respHeaders)
				}

				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				result.Release()
				failedInstances[instanceName] = true
				balancer.ClearSession(sessionKey)
				switchCount++
				failovers++
				switched = true
				observe.Global.FailoversTotal.Add(1)

			case RetryThenFailover:
				sameInstanceRetries++
				retries++
				observe.Global.RetriesTotal.Add(1)
				observe.Logger(ctx).Warn("retry on same instance",
					"instance", instanceName,
					"status", statusCode,
					"attempt", sameInstanceRetries,
					"max_attempts", maxSameInstanceRetries,
				)
				if sameInstanceRetries >= maxSameInstanceRetries {
					if resp != nil && resp.Body != nil {
						_ = resp.Body.Close()
					}
					balancer.ReportResult(ctx, instanceName, statusCode, attemptLatency, retryAfter, respHeaders)
					result.Release()
					failedInstances[instanceName] = true
					balancer.ClearSession(sessionKey)
					switchCount++
					failovers++
					switched = true
					observe.Global.FailoversTotal.Add(1)
					break
				}
				// Report the failed attempt (but don't trigger failover yet).
				balancer.ReportResult(ctx, instanceName, statusCode, attemptLatency, retryAfter, respHeaders)
				// Close previous response body before retrying.
				if resp != nil && resp.Body != nil {
					_ = resp.Body.Close()
				}
				// Exponential backoff before retry
				delay := RetryDelay(sameInstanceRetries - 1)
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
