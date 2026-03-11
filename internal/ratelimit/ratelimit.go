package ratelimit

import (
	"context"
	"sync"
	"time"
)

// visitor tracks request count within a sliding window for a single IP.
type visitor struct {
	count   int
	resetAt time.Time
}

// Limiter implements a per-IP fixed-window rate limiter.
// It allows up to rate requests per window duration for each unique IP.
type Limiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int
	window   time.Duration
}

// NewLimiter creates a rate limiter that allows rate requests per window per IP.
func NewLimiter(rate int, window time.Duration) *Limiter {
	return &Limiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}
}

// Allow reports whether a request from the given IP should be allowed.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	v, exists := l.visitors[ip]
	if !exists || now.After(v.resetAt) {
		l.visitors[ip] = &visitor{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	v.count++
	return v.count <= l.rate
}

// Window returns the configured window duration.
func (l *Limiter) Window() time.Duration {
	return l.window
}

// StartCleanup starts a background goroutine that removes expired visitors.
// It stops when the context is cancelled.
func (l *Limiter) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(l.window)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.cleanup()
			}
		}
	}()
}

// cleanup removes visitors whose window has expired.
func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for ip, v := range l.visitors {
		if now.After(v.resetAt) {
			delete(l.visitors, ip)
		}
	}
}
