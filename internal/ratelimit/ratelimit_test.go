package ratelimit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLimiter_Allow(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(3, time.Minute)

	ip := "192.168.1.1"
	for i := 0; i < 3; i++ {
		if !lim.Allow(ip) {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if lim.Allow(ip) {
		t.Fatal("4th request should be rejected")
	}
}

func TestLimiter_DifferentIPs(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(1, time.Minute)

	if !lim.Allow("10.0.0.1") {
		t.Fatal("first IP should be allowed")
	}
	if !lim.Allow("10.0.0.2") {
		t.Fatal("second IP should be allowed independently")
	}
	if lim.Allow("10.0.0.1") {
		t.Fatal("first IP should be rejected on second request")
	}
}

func TestLimiter_WindowReset(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(1, 50*time.Millisecond)

	if !lim.Allow("1.2.3.4") {
		t.Fatal("first request should be allowed")
	}
	if lim.Allow("1.2.3.4") {
		t.Fatal("second request should be rejected")
	}

	// Wait for window to expire.
	time.Sleep(60 * time.Millisecond)

	if !lim.Allow("1.2.3.4") {
		t.Fatal("request after window reset should be allowed")
	}
}

func TestMiddleware_Returns429(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(1, time.Minute)

	handler := Middleware(lim)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request — allowed.
	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: got status %d, want 200", rec.Code)
	}

	// Second request — rate limited.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request: got status %d, want 429", rec.Code)
	}

	// Verify Retry-After header.
	if ra := rec.Header().Get("Retry-After"); ra != "60" {
		t.Errorf("Retry-After = %q, want 60", ra)
	}

	// Verify Anthropic-style JSON body.
	var body struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if body.Type != "error" {
		t.Errorf("body.type = %q, want error", body.Type)
	}
	if body.Error.Type != "rate_limit_error" {
		t.Errorf("body.error.type = %q, want rate_limit_error", body.Error.Type)
	}
}

func TestMiddleware_XForwardedFor(t *testing.T) {
	t.Parallel()
	lim := NewLimiter(1, time.Minute)

	handler := Middleware(lim)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests from different X-Forwarded-For IPs should both be allowed.
	for _, ip := range []string{"10.0.0.1", "10.0.0.2"} {
		req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
		req.Header.Set("X-Forwarded-For", ip)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request from %s: got status %d, want 200", ip, rec.Code)
		}
	}
}

func TestClientIP(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		xff        string
		remoteAddr string
		want       string
	}{
		{"xff single", "1.2.3.4", "5.6.7.8:9999", "1.2.3.4"},
		{"xff multiple", "1.2.3.4, 5.6.7.8", "9.9.9.9:1234", "1.2.3.4"},
		{"no xff", "", "10.0.0.1:5555", "10.0.0.1"},
		{"no xff no port", "", "10.0.0.1", "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remoteAddr
			if tc.xff != "" {
				req.Header.Set("X-Forwarded-For", tc.xff)
			}
			got := clientIP(req)
			if got != tc.want {
				t.Errorf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
