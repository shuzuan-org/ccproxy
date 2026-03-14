package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// OAuthTokenProvider abstracts token retrieval to decouple from oauth.Manager.
type OAuthTokenProvider interface {
	GetValidToken(ctx context.Context, instanceName string) (accessToken string, err error)
}

// UsageResponse represents the Anthropic usage API response.
type UsageResponse struct {
	FiveHour       UsageWindowResponse `json:"five_hour"`
	SevenDay       UsageWindowResponse `json:"seven_day"`
	SevenDaySonnet UsageWindowResponse `json:"seven_day_sonnet"`
}

// UsageWindowResponse is a single window from the usage API.
type UsageWindowResponse struct {
	Utilization float64 `json:"utilization"` // 0-100
	ResetsAt    string  `json:"resets_at"`
}

type usageCacheEntry struct {
	resp      *UsageResponse
	fetchedAt time.Time
	isError   bool
}

const (
	usageCacheTTL      = 3 * time.Minute
	usageErrorCacheTTL = 1 * time.Minute
	usageCheckInterval = 3 * time.Minute
	usageStaleThreshold = 5 * time.Minute
	usageMaxJitter     = 800 * time.Millisecond
	usageAPIURL        = "https://api.anthropic.com/api/oauth/usage"
	usageAPIBeta       = "oauth-2025-04-20"
)

// UsageFetcher periodically fetches usage data from the Anthropic API
// to supplement response header data when headers are missing or stale.
type UsageFetcher struct {
	tokenProvider OAuthTokenProvider
	httpClient    *http.Client
	userAgent     string
	mu            sync.RWMutex
	cache         map[string]*usageCacheEntry
	inflight      singleflight.Group
}

// NewUsageFetcher creates a usage fetcher.
func NewUsageFetcher(tokenProvider OAuthTokenProvider, userAgent string) *UsageFetcher {
	return &UsageFetcher{
		tokenProvider: tokenProvider,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		userAgent: userAgent,
		cache:     make(map[string]*usageCacheEntry),
	}
}

// FetchIfNeeded checks if the budget has stale data and fetches if necessary.
// Returns the response or nil if fetch is not needed or fails.
func (uf *UsageFetcher) FetchIfNeeded(ctx context.Context, instanceName string, budget *BudgetController) *UsageResponse {
	if budget != nil && budget.HasRecentData(usageStaleThreshold) {
		return nil
	}

	// Check cache
	uf.mu.RLock()
	entry := uf.cache[instanceName]
	uf.mu.RUnlock()

	if entry != nil {
		ttl := usageCacheTTL
		if entry.isError {
			ttl = usageErrorCacheTTL
		}
		if time.Since(entry.fetchedAt) < ttl {
			return entry.resp
		}
	}

	return uf.fetch(ctx, instanceName)
}

// fetchFromURL fetches usage data from a specific URL (for testing).
func (uf *UsageFetcher) fetchFromURL(ctx context.Context, instanceName, url string) *UsageResponse {
	// Check cache first
	uf.mu.RLock()
	entry := uf.cache[instanceName]
	uf.mu.RUnlock()

	if entry != nil {
		ttl := usageCacheTTL
		if entry.isError {
			ttl = usageErrorCacheTTL
		}
		if time.Since(entry.fetchedAt) < ttl {
			return entry.resp
		}
	}

	return uf.doFetch(ctx, instanceName, url)
}

func (uf *UsageFetcher) fetch(ctx context.Context, instanceName string) *UsageResponse {
	return uf.doFetch(ctx, instanceName, usageAPIURL)
}

func (uf *UsageFetcher) doFetch(ctx context.Context, instanceName, apiURL string) *UsageResponse {
	// Use singleflight to deduplicate concurrent fetches for the same instance
	result, err, _ := uf.inflight.Do(instanceName, func() (interface{}, error) {
		// Random jitter before fetch
		jitter := time.Duration(rand.Int63n(int64(usageMaxJitter)))
		timer := time.NewTimer(jitter)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}

		token, err := uf.tokenProvider.GetValidToken(ctx, instanceName)
		if err != nil {
			slog.Debug("usage: token error", "instance", instanceName, "error", err.Error())
			uf.cacheError(instanceName)
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("anthropic-beta", usageAPIBeta)
		if uf.userAgent != "" {
			req.Header.Set("User-Agent", uf.userAgent)
		}

		resp, err := uf.httpClient.Do(req)
		if err != nil {
			slog.Debug("usage: fetch error", "instance", instanceName, "error", err.Error())
			uf.cacheError(instanceName)
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			slog.Warn("usage: API error", "instance", instanceName, "status", resp.StatusCode, "body", string(body))
			uf.cacheError(instanceName)
			return nil, fmt.Errorf("usage API returned %d", resp.StatusCode)
		}

		var usageResp UsageResponse
		if err := json.NewDecoder(resp.Body).Decode(&usageResp); err != nil {
			slog.Warn("usage: decode error", "instance", instanceName, "error", err.Error())
			uf.cacheError(instanceName)
			return nil, err
		}

		uf.cacheSuccess(instanceName, &usageResp)
		slog.Debug("usage: fetched",
			"instance", instanceName,
			"5h_util", usageResp.FiveHour.Utilization,
			"7d_util", usageResp.SevenDay.Utilization,
		)
		return &usageResp, nil
	})

	if err != nil {
		return nil
	}
	return result.(*UsageResponse)
}

func (uf *UsageFetcher) cacheSuccess(instanceName string, resp *UsageResponse) {
	uf.mu.Lock()
	uf.cache[instanceName] = &usageCacheEntry{
		resp:      resp,
		fetchedAt: time.Now(),
		isError:   false,
	}
	uf.mu.Unlock()
}

func (uf *UsageFetcher) cacheError(instanceName string) {
	uf.mu.Lock()
	uf.cache[instanceName] = &usageCacheEntry{
		resp:      nil,
		fetchedAt: time.Now(),
		isError:   true,
	}
	uf.mu.Unlock()
}

// StartBackground starts a background goroutine that periodically checks
// all instances and fetches usage data when needed.
func (uf *UsageFetcher) StartBackground(
	ctx context.Context,
	getInstanceNames func() []string,
	getBudget func(string) *BudgetController,
) {
	go func() {
		ticker := time.NewTicker(usageCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				names := getInstanceNames()
				for _, name := range names {
					budget := getBudget(name)
					resp := uf.FetchIfNeeded(ctx, name, budget)
					if resp != nil && budget != nil {
						budget.UpdateFromUsageAPI(
							UsageAPIWindow{Utilization: resp.FiveHour.Utilization, ResetsAt: resp.FiveHour.ResetsAt},
							UsageAPIWindow{Utilization: resp.SevenDay.Utilization, ResetsAt: resp.SevenDay.ResetsAt},
						)
					}
				}
			}
		}
	}()
}
