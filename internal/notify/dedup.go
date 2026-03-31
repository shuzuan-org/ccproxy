package notify

import (
	"fmt"
	"sync"
	"time"
)

// Dedup suppresses repeated notifications for the same account+event within a TTL window.
type Dedup struct {
	mu      sync.Mutex
	entries map[string]time.Time
	ttl     time.Duration
}

// NewDedup creates a Dedup with the given TTL.
func NewDedup(ttl time.Duration) *Dedup {
	return &Dedup{
		entries: make(map[string]time.Time),
		ttl:     ttl,
	}
}

// Allow returns true if the event should be sent (not seen within TTL), and records
// the current time. Returns false if the same account+event was seen within the TTL.
func (d *Dedup) Allow(account string, event EventType) bool {
	key := fmt.Sprintf("%s:%s", account, string(event))
	d.mu.Lock()
	defer d.mu.Unlock()
	if last, ok := d.entries[key]; ok && time.Since(last) < d.ttl {
		return false
	}
	d.entries[key] = time.Now()
	return true
}
