package notify

import (
	"context"
	"log/slog"
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
	EventBudgetBlocked   EventType = "budget_blocked"   // budget state �� Blocked
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

// OwnerResolver looks up the owner of an account by name.
type OwnerResolver func(accountName string) string

// NotifierRegistry manages per-user notifiers and dispatches events.
type NotifierRegistry struct {
	mu       sync.RWMutex
	entries  map[string]Notifier // username → notifier
	resolver OwnerResolver       // resolves account name → owner username
}

// NewRegistry creates a NotifierRegistry with the given owner resolver.
func NewRegistry(resolver OwnerResolver) *NotifierRegistry {
	return &NotifierRegistry{
		entries:  make(map[string]Notifier),
		resolver: resolver,
	}
}

// Set registers a notifier for the given username.
func (r *NotifierRegistry) Set(username string, n Notifier) {
	r.mu.Lock()
	r.entries[username] = n
	r.mu.Unlock()
}

// Remove unregisters the notifier for the given username.
func (r *NotifierRegistry) Remove(username string) {
	r.mu.Lock()
	delete(r.entries, username)
	r.mu.Unlock()
}

// NotifyAll dispatches an event to all registered notifiers.
// - admin: receives events filtered by their own config (EnableDisabled/EnableAnomaly)
// - users: only receive CategoryDisabled events for accounts they own
func (r *NotifierRegistry) NotifyAll(ctx context.Context, event Event) {
	r.mu.RLock()
	snapshot := make(map[string]Notifier, len(r.entries))
	for k, v := range r.entries {
		snapshot[k] = v
	}
	r.mu.RUnlock()

	owner := ""
	if r.resolver != nil {
		owner = r.resolver(event.AccountName)
	}

	for username, notifier := range snapshot {
		if username == "admin" {
			// Admin receives all events; TelegramNotifier handles category filtering.
			if err := notifier.Notify(ctx, event); err != nil {
				slog.Debug("notify: admin dispatch failed", "error", err)
			}
		} else {
			// Users only receive CategoryDisabled events for their own accounts.
			if owner != username {
				continue
			}
			if event.Type.Category() != CategoryDisabled {
				continue
			}
			if err := notifier.Notify(ctx, event); err != nil {
				slog.Debug("notify: user dispatch failed", "username", username, "error", err)
			}
		}
	}
}

// Global registry instance.
var (
	globalMu       sync.RWMutex
	globalRegistry *NotifierRegistry
)

// SetGlobalRegistry sets the global notifier registry.
func SetGlobalRegistry(r *NotifierRegistry) {
	globalMu.Lock()
	globalRegistry = r
	globalMu.Unlock()
}

// GlobalRegistry returns the global notifier registry, or nil if not set.
func GlobalRegistry() *NotifierRegistry {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalRegistry
}

// NotifyAll dispatches an event via the global registry.
// No-op if the global registry is not set.
func NotifyAllGlobal(ctx context.Context, event Event) {
	reg := GlobalRegistry()
	if reg != nil {
		reg.NotifyAll(ctx, event)
	}
}
