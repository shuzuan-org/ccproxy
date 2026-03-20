package loadbalancer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

type mockTokenProvider struct {
	token string
	err   error
}

func (m *mockTokenProvider) GetValidToken(_ context.Context, _ string) (string, error) {
	return m.token, m.err
}

func TestUsageFetcher_FetchSuccess(t *testing.T) {
	t.Parallel()

	resp := UsageResponse{
		FiveHour: UsageWindowResponse{Utilization: 42.5, ResetsAt: "2026-03-14T12:00:00Z"},
		SevenDay: UsageWindowResponse{Utilization: 65.0, ResetsAt: "2026-03-20T00:00:00Z"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing Authorization header")
		}
		if r.Header.Get("anthropic-beta") != usageAPIBeta {
			t.Error("missing anthropic-beta header")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	uf := NewUsageFetcher(&mockTokenProvider{token: "test-token"}, "test-ua")
	uf.httpClient = server.Client()

	// Override the URL by creating a custom fetch
	origURL := usageAPIURL
	_ = origURL // usageAPIURL is const, we test via httptest by overriding httpClient

	// Direct fetch test: we'll call fetch with the test server
	ctx := context.Background()
	result := uf.fetchFromURL(ctx, "inst1", server.URL)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.FiveHour.Utilization != 42.5 {
		t.Errorf("5h util = %f, want 42.5", result.FiveHour.Utilization)
	}
	if result.SevenDay.Utilization != 65.0 {
		t.Errorf("7d util = %f, want 65.0", result.SevenDay.Utilization)
	}
}

func TestUsageFetcher_CacheHit(t *testing.T) {
	t.Parallel()

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		_ = json.NewEncoder(w).Encode(UsageResponse{
			FiveHour: UsageWindowResponse{Utilization: 10},
			SevenDay: UsageWindowResponse{Utilization: 20},
		})
	}))
	defer server.Close()

	uf := NewUsageFetcher(&mockTokenProvider{token: "tok"}, "")
	uf.httpClient = server.Client()

	ctx := context.Background()
	// First fetch
	uf.fetchFromURL(ctx, "inst1", server.URL)
	// Second fetch should hit cache
	uf.fetchFromURL(ctx, "inst1", server.URL)

	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount.Load())
	}
}

func TestUsageFetcher_ErrorCacheShortTTL(t *testing.T) {
	t.Parallel()

	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	uf := NewUsageFetcher(&mockTokenProvider{token: "tok"}, "")
	uf.httpClient = server.Client()

	ctx := context.Background()
	// First fetch (error)
	uf.fetchFromURL(ctx, "inst1", server.URL)
	// Should be cached, so same count
	uf.fetchFromURL(ctx, "inst1", server.URL)
	if fetchCount.Load() != 1 {
		t.Errorf("expected 1 fetch with error cache, got %d", fetchCount.Load())
	}

	// Expire error cache
	uf.mu.Lock()
	uf.cache["inst1"].fetchedAt = time.Now().Add(-2 * usageErrorCacheTTL)
	uf.mu.Unlock()

	// Should fetch again
	uf.fetchFromURL(ctx, "inst1", server.URL)
	if fetchCount.Load() != 2 {
		t.Errorf("expected 2 fetches after error cache expiry, got %d", fetchCount.Load())
	}
}

func TestUsageFetcher_FetchIfNeeded_RecentData(t *testing.T) {
	t.Parallel()

	uf := NewUsageFetcher(&mockTokenProvider{token: "tok"}, "")
	budget := NewBudgetController("test")

	// Set recent data
	h := http.Header{}
	h.Set("anthropic-ratelimit-unified-5h-utilization", "0.3")
	budget.UpdateFromHeaders(context.Background(), h)

	// Should not fetch because budget has recent data
	result := uf.FetchIfNeeded(context.Background(), "inst1", budget)
	if result != nil {
		t.Error("expected nil result when budget has recent data")
	}
}

func TestUsageFetcher_BansAccount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		wantReason string
	}{
		{name: "403 body", statusCode: http.StatusForbidden, body: `{"error":{"message":"forbidden"}}`, wantReason: PlatformBanReasonForbidden},
		{name: "oauth not allowed", statusCode: http.StatusForbidden, body: `{"error":{"message":"OAuth authentication is currently not allowed for this organization."}}`, wantReason: PlatformBanReasonOAuthNotAllowed},
		{name: "organization disabled", statusCode: http.StatusForbidden, body: `{"error":{"message":"organization disabled"}}`, wantReason: PlatformBanReasonOrganizationDisabled},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var bannedAccount, bannedReason string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			uf := NewUsageFetcher(&mockTokenProvider{token: "tok"}, "")
			uf.httpClient = server.Client()
			uf.SetOnPlatformBan(func(accountName, reason string) {
				bannedAccount = accountName
				bannedReason = reason
			})

			resp := uf.fetchFromURL(context.Background(), "acct1", server.URL)
			if resp != nil {
				t.Fatal("expected nil response on API error")
			}
			if bannedAccount != "acct1" {
				t.Fatalf("expected banned account acct1, got %q", bannedAccount)
			}
			if bannedReason != tt.wantReason {
				t.Fatalf("expected ban reason %q, got %q", tt.wantReason, bannedReason)
			}
		})
	}
}

func TestUsageFetcher_DoesNotBan(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		provider   *mockTokenProvider
	}{
		{name: "401", statusCode: http.StatusUnauthorized, body: `{"error":{"message":"unauthorized"}}`, provider: &mockTokenProvider{token: "tok"}},
		{name: "429", statusCode: http.StatusTooManyRequests, body: `{"error":{"message":"rate limited"}}`, provider: &mockTokenProvider{token: "tok"}},
		{name: "529", statusCode: 529, body: `{"error":{"message":"overloaded"}}`, provider: &mockTokenProvider{token: "tok"}},
		{name: "network error", provider: &mockTokenProvider{err: errors.New("token unavailable")}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			called := false
			uf := NewUsageFetcher(tt.provider, "")
			uf.SetOnPlatformBan(func(accountName, reason string) {
				called = true
			})

			if tt.provider.err == nil {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.statusCode)
					_, _ = w.Write([]byte(tt.body))
				}))
				defer server.Close()
				uf.httpClient = server.Client()
				_ = uf.fetchFromURL(context.Background(), "acct1", server.URL)
			} else {
				_ = uf.fetchFromURL(context.Background(), "acct1", "http://example.invalid")
			}

			if called {
				t.Fatal("expected no ban callback")
			}
		})
	}
}

func TestBalancer_SetUsageFetcherWiresPlatformBan(t *testing.T) {
	t.Parallel()

	b := NewBalancer([]config.AccountConfig{{Name: "acct1", MaxConcurrency: 1, Enabled: true}}, NewConcurrencyTracker())
	uf := NewUsageFetcher(&mockTokenProvider{token: "tok"}, "")
	b.SetUsageFetcher(uf)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"message":"organization disabled"}}`))
	}))
	defer server.Close()
	uf.httpClient = server.Client()

	_ = uf.fetchFromURL(context.Background(), "acct1", server.URL)

	h := b.GetHealth("acct1")
	if h == nil {
		t.Fatal("expected health tracker")
	}
	if !h.IsBanned() {
		t.Fatal("expected account to be marked banned")
	}
	if got := h.BanReason(); got != PlatformBanReasonOrganizationDisabled {
		t.Fatalf("expected ban reason %q, got %q", PlatformBanReasonOrganizationDisabled, got)
	}
}
