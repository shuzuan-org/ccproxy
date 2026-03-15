package loadbalancer

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/config"
	"github.com/binn/ccproxy/internal/observe"
	"github.com/google/uuid"
)

var (
	ErrNoHealthyAccounts = errors.New("no healthy accounts available")
	ErrAllAccountsBusy   = errors.New("all accounts at capacity")
)

const sessionTTL = 1 * time.Hour

type SessionInfo struct {
	AccountName string
	LastRequest time.Time
}

type SelectResult struct {
	Account   config.AccountConfig
	RequestID string
	Release   func()
}

type Balancer struct {
	mu           sync.RWMutex
	accounts     []config.AccountConfig
	tracker      *ConcurrencyTracker
	health       map[string]*AccountHealth // per-account health tracking
	sessions     sync.Map                  // sessionKey → *SessionInfo
	lastUsed     sync.Map                  // accountName → time.Time
	throttle     *PoolThrottle
	usageFetcher *UsageFetcher
}

func NewBalancer(accounts []config.AccountConfig, tracker *ConcurrencyTracker) *Balancer {
	enabled := filterEnabled(accounts)
	health := make(map[string]*AccountHealth, len(enabled))
	for _, acct := range enabled {
		health[acct.Name] = NewAccountHealth(acct.Name)
	}
	queueCap := len(enabled) * 3
	if queueCap < 10 {
		queueCap = 10
	}
	return &Balancer{
		accounts: enabled,
		tracker:  tracker,
		health:   health,
		throttle: NewPoolThrottle(queueCap),
	}
}

func filterEnabled(accounts []config.AccountConfig) []config.AccountConfig {
	var result []config.AccountConfig
	for _, acct := range accounts {
		if acct.IsEnabled() {
			result = append(result, acct)
		}
	}
	return result
}

// SetUsageFetcher injects the usage fetcher after construction.
func (b *Balancer) SetUsageFetcher(f *UsageFetcher) {
	b.usageFetcher = f
}

// accountCandidate holds a candidate account for selection.
type accountCandidate struct {
	account  config.AccountConfig
	loadRate int
	lastUsed time.Time
	score    float64
}

// SelectAccount implements 3-layer selection with pool-level backpressure:
// L1 Pool: SRE throttling + utilization delay + wait queue
// L2 Sticky: Session affinity (1h TTL) with budget-aware concurrency
// L3 Score: Load-aware selection with budget state filtering
func (b *Balancer) SelectAccount(ctx context.Context, sessionKey string, excludeAccounts map[string]bool, isStream bool) (*SelectResult, error) {
	// L1: Pool-level backpressure
	b.throttle.RecordRequest()
	if b.throttle.ShouldThrottle() {
		observe.Global.RequestsThrottled.Add(1)
		observe.Global.RequestsQueued.Add(1)
		if !b.throttle.Enqueue(ctx, isStream) {
			return nil, ErrAllAccountsBusy
		}
		defer b.throttle.Dequeue()
	}

	// Utilization-based delay
	budgets := b.allBudgets()
	poolUtil := PoolUtilization(budgets)
	if delay := UtilizationDelay(poolUtil); delay > 0 {
		observe.Logger(ctx).Debug("backpressure: utilization delay", "pool_util", poolUtil, "delay", delay.String())
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}

	b.mu.RLock()
	accounts := b.accounts
	health := b.health
	b.mu.RUnlock()

	if len(accounts) == 0 {
		return nil, ErrNoHealthyAccounts
	}

	requestID := uuid.New().String()

	// Layer 2: Sticky session check
	if sessionKey != "" {
		if info, ok := b.sessions.Load(sessionKey); ok {
			si := info.(*SessionInfo)
			if time.Since(si.LastRequest) < sessionTTL {
				acct := b.findAccount(si.AccountName)
				if acct != nil && !excludeAccounts[acct.Name] {
					h := health[acct.Name]
					if h == nil || h.IsAvailable() {
						// Use dynamic concurrency for sticky sessions
						effectiveMax := acct.MaxConcurrency
						if h != nil {
							effectiveMax = EffectiveMaxConcurrency(h.budget, acct.MaxConcurrency)
						}
						rate := b.tracker.LoadRate(acct.Name, effectiveMax)
						if rate < 100 {
							if release, ok := b.tracker.Acquire(acct.Name, requestID, effectiveMax); ok {
								b.sessions.Store(sessionKey, &SessionInfo{
									AccountName: si.AccountName,
									LastRequest: time.Now(),
								})
								return &SelectResult{Account: *acct, RequestID: requestID, Release: release}, nil
							}
						}
					}
				}
			}
			// Sticky session expired or account unavailable
			b.sessions.Delete(sessionKey)
		}
	}

	// Layer 3: Score-based selection with budget state filtering
	candidates := make([]accountCandidate, 0, len(accounts))
	for _, acct := range accounts {
		if excludeAccounts[acct.Name] {
			continue
		}
		h := health[acct.Name]
		if h != nil && !h.IsAvailable() {
			continue
		}

		// Check budget state — skip Blocked and StickyOnly accounts
		if h != nil && h.budget != nil {
			state := h.budget.State()
			if state == StateBlocked || state == StateStickyOnly {
				observe.Logger(ctx).Debug("balancer: account filtered",
					"account", acct.Name,
					"reason", state.String(),
				)
				continue
			}
		}

		effectiveMax := acct.MaxConcurrency
		if h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, acct.MaxConcurrency)
		}
		rate := b.tracker.LoadRate(acct.Name, effectiveMax)
		if rate >= 100 {
			continue
		}
		var lu time.Time
		if v, ok := b.lastUsed.Load(acct.Name); ok {
			lu = v.(time.Time)
		}
		score := 0.0
		if h != nil {
			score = h.Score(rate)
		}
		candidates = append(candidates, accountCandidate{
			account: acct, loadRate: rate, lastUsed: lu, score: score,
		})
	}

	if len(candidates) == 0 {
		return nil, ErrAllAccountsBusy
	}

	// Short-circuit: single candidate, no sorting needed
	if len(candidates) == 1 {
		c := candidates[0]
		effectiveMax := c.account.MaxConcurrency
		if h := health[c.account.Name]; h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, c.account.MaxConcurrency)
		}
		if release, ok := b.tracker.Acquire(c.account.Name, requestID, effectiveMax); ok {
			b.lastUsed.Store(c.account.Name, time.Now())
			return &SelectResult{Account: c.account, RequestID: requestID, Release: release}, nil
		}
		return nil, ErrAllAccountsBusy
	}

	// Two candidates: simple comparison instead of sort.Slice
	if len(candidates) == 2 {
		a, z := candidates[0], candidates[1]
		if a.score > z.score || (a.score == z.score && a.lastUsed.After(z.lastUsed)) {
			candidates[0], candidates[1] = z, a
		}
	} else {
		// Sort by Score (lower = better), break ties with LRU
		sort.Slice(candidates, func(i, j int) bool {
			if candidates[i].score != candidates[j].score {
				return candidates[i].score < candidates[j].score
			}
			return candidates[i].lastUsed.Before(candidates[j].lastUsed)
		})
	}

	// Try to acquire slot
	for _, c := range candidates {
		effectiveMax := c.account.MaxConcurrency
		if h := health[c.account.Name]; h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, c.account.MaxConcurrency)
		}
		if release, ok := b.tracker.Acquire(c.account.Name, requestID, effectiveMax); ok {
			b.lastUsed.Store(c.account.Name, time.Now())
			observe.Logger(ctx).Debug("balancer: account selected",
				"account", c.account.Name,
				"score", c.score,
				"candidates", len(candidates),
			)
			return &SelectResult{Account: c.account, RequestID: requestID, Release: release}, nil
		}
	}

	return nil, ErrAllAccountsBusy
}

func (b *Balancer) findAccount(name string) *config.AccountConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, acct := range b.accounts {
		if acct.Name == name {
			found := acct
			return &found
		}
	}
	return nil
}

// BindSession creates or updates a sticky session binding.
func (b *Balancer) BindSession(sessionKey, accountName string) {
	if sessionKey == "" {
		return
	}
	b.sessions.Store(sessionKey, &SessionInfo{
		AccountName: accountName,
		LastRequest: time.Now(),
	})
}

// ClearSession removes a sticky session binding.
func (b *Balancer) ClearSession(sessionKey string) {
	b.sessions.Delete(sessionKey)
}

// UpdateAccounts atomically replaces the account list (for hot-reload),
// preserving health state for existing accounts and cleaning up removed ones.
func (b *Balancer) UpdateAccounts(accounts []config.AccountConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.accounts = filterEnabled(accounts)

	newHealth := make(map[string]*AccountHealth, len(b.accounts))
	var added, removed []string
	for _, acct := range b.accounts {
		if existing, ok := b.health[acct.Name]; ok {
			newHealth[acct.Name] = existing
		} else {
			newHealth[acct.Name] = NewAccountHealth(acct.Name)
			added = append(added, acct.Name)
		}
	}
	for name := range b.health {
		if _, ok := newHealth[name]; !ok {
			removed = append(removed, name)
		}
	}
	b.health = newHealth

	// Clean up tracker entries for removed accounts
	for _, name := range removed {
		b.tracker.RemoveAccount(name)
	}

	if len(added) > 0 || len(removed) > 0 {
		slog.Info("balancer: accounts updated",
			"total", len(b.accounts),
			"added", added,
			"removed", removed,
		)
	}
}

// StartCleanup starts background goroutines for session and stale slot cleanup.
func (b *Balancer) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.cleanupSessions()
				b.tracker.CleanupStale()
			}
		}
	}()
}

func (b *Balancer) cleanupSessions() {
	b.sessions.Range(func(key, value interface{}) bool {
		si := value.(*SessionInfo)
		if time.Since(si.LastRequest) >= sessionTTL {
			b.sessions.Delete(key)
		}
		return true
	})
}

// ReportResult reports a request outcome to the health tracker for the given account.
func (b *Balancer) ReportResult(ctx context.Context, accountName string, statusCode int, latencyUs int64, retryAfter time.Duration, responseHeaders http.Header) {
	b.mu.RLock()
	h := b.health[accountName]
	b.mu.RUnlock()
	if h == nil {
		return
	}
	if statusCode >= 200 && statusCode < 400 {
		h.RecordSuccess(ctx, latencyUs)
		// Update budget from response headers on success
		if responseHeaders != nil {
			h.budget.UpdateFromHeaders(ctx, responseHeaders)
		}
		// Record accept for SRE throttle
		b.throttle.RecordAccept()
		// Trigger usage fetch if budget data is stale
		if b.usageFetcher != nil && !h.budget.HasRecentData(usageStaleThreshold) {
			go b.usageFetcher.FetchIfNeeded(context.Background(), accountName, h.budget)
		}
	} else {
		h.RecordError(ctx, statusCode, retryAfter, responseHeaders)
	}
}

// GetHealth returns the health tracker for a specific account.
func (b *Balancer) GetHealth(accountName string) *AccountHealth {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.health[accountName]
}

// AllHealth returns a snapshot of all health trackers.
func (b *Balancer) AllHealth() map[string]*AccountHealth {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]*AccountHealth, len(b.health))
	for k, v := range b.health {
		result[k] = v
	}
	return result
}

// AccountStates returns a snapshot of all account states for observability.
func (b *Balancer) AccountStates() map[string]observe.AccountState {
	b.mu.RLock()
	defer b.mu.RUnlock()
	states := make(map[string]observe.AccountState, len(b.accounts))
	for _, acct := range b.accounts {
		name := acct.Name
		state := observe.AccountState{
			Concurrency:    b.tracker.ActiveSlots(name),
			MaxConcurrency: acct.MaxConcurrency,
		}
		if h, ok := b.health[name]; ok {
			if h.IsDisabled() {
				state.Health = "disabled"
			} else if !h.IsAvailable() {
				state.Health = "cooldown"
			} else {
				state.Health = "healthy"
			}
			state.BudgetState = h.Budget().State().String()
		}
		states[name] = state
	}
	return states
}

// GetAccounts returns current account list (for admin API).
func (b *Balancer) GetAccounts() []config.AccountConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]config.AccountConfig, len(b.accounts))
	copy(result, b.accounts)
	return result
}

// GetTracker returns the concurrency tracker (for admin API).
func (b *Balancer) GetTracker() *ConcurrencyTracker {
	return b.tracker
}

// ActiveSessions returns count of active sessions.
func (b *Balancer) ActiveSessions() int {
	count := 0
	b.sessions.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// allBudgets returns a snapshot of all budget controllers.
func (b *Balancer) allBudgets() map[string]*BudgetController {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make(map[string]*BudgetController, len(b.health))
	for name, h := range b.health {
		result[name] = h.budget
	}
	return result
}
