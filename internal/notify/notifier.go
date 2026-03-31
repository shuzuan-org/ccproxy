package notify

import (
	"context"
	"sync"
)

// EventType identifies a specific account anomaly event.
type EventType string

const (
	// CategoryDisabled events — permanent, require manual intervention.
	EventAccountDisabled EventType = "account_disabled" // consecutive 401s
	EventAccountBanned   EventType = "account_banned"   // platform ban (403/400)

	// CategoryAnomaly events — recoverable.
	EventRateLimited     EventType = "rate_limited"     // true 429 with reset headers
	EventOverloaded      EventType = "overloaded"       // 529
	EventTimeoutCooldown EventType = "timeout_cooldown" // timeout threshold reached
	EventBudgetBlocked   EventType = "budget_blocked"   // budget state → Blocked
)

// EventCategory classifies an event for subscription filtering.
type EventCategory int

const (
	CategoryDisabled EventCategory = iota // account permanently disabled
	CategoryAnomaly                       // recoverable anomaly
)

// Category returns the category of this event type.
func (e EventType) Category() EventCategory {
	switch e {
	case EventAccountDisabled, EventAccountBanned:
		return CategoryDisabled
	default:
		return CategoryAnomaly
	}
}

// Event represents an account anomaly to be notified.
type Event struct {
	AccountName string
	Type        EventType
	Detail      string // human-readable context, e.g. "cooldown: 60s"
}

// Notifier sends account anomaly notifications.
type Notifier interface {
	Notify(ctx context.Context, event Event) error
}

// NoopNotifier discards all notifications. Used as default before config is loaded.
type NoopNotifier struct{}

func (n *NoopNotifier) Notify(_ context.Context, _ Event) error { return nil }

var (
	globalMu sync.RWMutex
	global   Notifier = &NoopNotifier{}
)

// SetGlobal replaces the active Notifier. Safe for concurrent use.
func SetGlobal(n Notifier) {
	globalMu.Lock()
	global = n
	globalMu.Unlock()
}

// Global returns the active Notifier. Safe for concurrent use.
func Global() Notifier {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}
