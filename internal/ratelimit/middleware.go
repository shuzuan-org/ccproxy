package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware that rate-limits requests by client IP.
// When the limit is exceeded, it responds with HTTP 429 and an Anthropic-style
// JSON error body.
func Middleware(limiter *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !limiter.Allow(ip) {
				retryAfter := int(limiter.Window().Seconds())
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"type":"error","error":{"type":"rate_limit_error","message":"Too many requests. Please try again later."}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP from the request, preferring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs: client, proxy1, proxy2.
		// The first one is the original client.
		if i := strings.IndexByte(xff, ','); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}

	// Fall back to RemoteAddr, stripping port.
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
