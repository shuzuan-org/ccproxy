package ratelimit

import (
	"fmt"
	"net"
	"net/http"

	"github.com/binn/ccproxy/internal/apierror"
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
				w.Header().Set("Retry-After", fmt.Sprintf("%d", retryAfter))
				apierror.Write(w, http.StatusTooManyRequests, "rate_limit_error", "Too many requests. Please try again later.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the client IP from the request using RemoteAddr only.
// X-Forwarded-For is intentionally ignored to prevent IP spoofing.
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
