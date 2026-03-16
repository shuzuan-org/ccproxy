package loadbalancer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/binn/ccproxy/internal/observe"
)

// OAuthTokenProvider abstracts token retrieval to decouple from oauth.Manager.
type OAuthTokenProvider interface {
	GetValidToken(ctx context.Context, accountName string) (accessToken string, err error)
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
func (uf *UsageFetcher) FetchIfNeeded(ctx context.Context, accountName string, budget *BudgetController) *UsageResponse {
	if budget != nil && budget.HasRecentData(usageStaleThreshold) {
		return nil
	}

	// Check cache
	uf.mu.RLock()
	entry := uf.cache[accountName]
	uf.mu.RUnlock()

	if entry != nil {
		ttl := usageCacheTTL
		if entry.isError {
			ttl = usageErrorCacheTTL
		}
		if time.Since(entry.fetchedAt) < ttl {
			observe.Logger(ctx).Debug("usage: cache hit", "account", accountName)
			return entry.resp
		}
	}

	return uf.fetch(ctx, accountName)
}

// fetchFromURL fetches usage data from a specific URL (for testing).
func (uf *UsageFetcher) fetchFromURL(ctx context.Context, accountName, url string) *UsageResponse {
	// Check cache first
	uf.mu.RLock()
	entry := uf.cache[accountName]
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

	return uf.doFetch(ctx, accountName, url)
}

func (uf *UsageFetcher) fetch(ctx context.Context, accountName string) *UsageResponse {
	return uf.doFetch(ctx, accountName, usageAPIURL)
}

func (uf *UsageFetcher) doFetch(ctx context.Context, accountName, apiURL string) *UsageResponse {
	// Use singleflight to deduplicate concurrent fetches for the same account
	result, err, _ := uf.inflight.Do(accountName, func() (interface{}, error) {
		// Random jitter before fetch
		jitter := time.Duration(rand.Int63n(int64(usageMaxJitter)))
		timer := time.NewTimer(jitter)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}

		token, err := uf.tokenProvider.GetValidToken(ctx, accountName)
		if err != nil {
			observe.Logger(ctx).Debug("usage: token error", "account", accountName, "error", err.Error())
			uf.cacheError(accountName)
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
			observe.Logger(ctx).Debug("usage: fetch error", "account", accountName, "error", err.Error())
			uf.cacheError(accountName)
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			observe.Logger(ctx).Warn("usage: API error", "account", accountName, "status", resp.StatusCode, "body", string(body))
			uf.cacheError(accountName)
			return nil, fmt.Errorf("usage API returned %d", resp.StatusCode)
		}

		var usageResp UsageResponse
		if err := json.NewDecoder(resp.Body).Decode(&usageResp); err != nil {
			observe.Logger(ctx).Warn("usage: decode error", "account", accountName, "error", err.Error())
			uf.cacheError(accountName)
			return nil, err
		}

		uf.cacheSuccess(accountName, &usageResp)
		observe.Logger(ctx).Debug("usage: fetched",
			"account", accountName,
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

func (uf *UsageFetcher) cacheSuccess(accountName string, resp *UsageResponse) {
	uf.mu.Lock()
	uf.cache[accountName] = &usageCacheEntry{
		resp:      resp,
		fetchedAt: time.Now(),
		isError:   false,
	}
	uf.mu.Unlock()
}

func (uf *UsageFetcher) cacheError(accountName string) {
	uf.mu.Lock()
	uf.cache[accountName] = &usageCacheEntry{
		resp:      nil,
		fetchedAt: time.Now(),
		isError:   true,
	}
	uf.mu.Unlock()
}

// StartBackground starts a background goroutine that periodically checks
// all accounts and fetches usage data when needed.
func (uf *UsageFetcher) StartBackground(
	ctx context.Context,
	getAccountNames func() []string,
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
				names := getAccountNames()
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
