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
	AccountID string
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
	health       map[string]*AccountHealth // per-account health tracking (key: account ID)
	sessions     sync.Map                  // sessionKey → *SessionInfo
	lastUsed     sync.Map                  // accountID → time.Time
	throttle     *PoolThrottle
	usageFetcher *UsageFetcher
}

func NewBalancer(accounts []config.AccountConfig, tracker *ConcurrencyTracker) *Balancer {
	enabled := filterEnabled(accounts)
	health := make(map[string]*AccountHealth, len(enabled))
	for _, acct := range enabled {
		health[acct.ID] = NewAccountHealth(acct.ID, acct.Name)
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
	if f != nil {
		f.SetOnPlatformBan(func(accountID, reason string) {
			if h := b.GetHealth(accountID); h != nil {
				h.Disable(reason)
			}
		})
	}
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
			expired := time.Since(si.LastRequest) >= sessionTTL
			deleteSession := expired // only delete on true expiry

			if !expired {
				acct := b.findAccount(si.AccountID)
				if acct != nil && !excludeAccounts[acct.ID] {
					h := health[acct.ID]
					if h == nil || h.IsAvailable() {
						if h != nil && h.budget != nil && h.budget.State() == StateBlocked {
							observe.Logger(ctx).Debug("balancer: sticky session skipped (budget blocked)",
								"account", acct.Name,
								"session_key", sessionKey,
							)
						} else {
							// Use dynamic concurrency for sticky sessions
							effectiveMax := acct.MaxConcurrency
							if h != nil {
								effectiveMax = EffectiveMaxConcurrency(h.budget, acct.MaxConcurrency)
							}
							rate := b.tracker.LoadRate(acct.ID, effectiveMax)
							if rate < 100 {
								if release, ok := b.tracker.Acquire(acct.ID, requestID, effectiveMax); ok {
									b.sessions.Store(sessionKey, &SessionInfo{
										AccountID: si.AccountID,
										LastRequest: time.Now(),
									})
									observe.Logger(ctx).Debug("balancer: sticky session hit",
										"account", acct.Name,
										"session_key", sessionKey,
									)
									return &SelectResult{Account: *acct, RequestID: requestID, Release: release}, nil
								}
							} else {
								observe.Logger(ctx).Debug("balancer: sticky session skipped (overloaded)",
									"account", acct.Name,
									"load_rate", rate,
								)
							}
						}
					} else {
						observe.Logger(ctx).Debug("balancer: sticky session skipped (unavailable)",
							"account", acct.Name,
						)
						deleteSession = true
					}
				} else {
					// Account removed or excluded — clean up binding
					deleteSession = true
				}
			}

			if deleteSession {
				observe.Logger(ctx).Debug("balancer: sticky session removed",
					"session_key", sessionKey,
					"expired", expired,
				)
				b.sessions.Delete(sessionKey)
			}
		}
	}

	// Layer 3: Score-based selection with budget state filtering
	candidates := make([]accountCandidate, 0, len(accounts))
	filteredBudget := 0
	filteredLoad := 0
	for _, acct := range accounts {
		if excludeAccounts[acct.ID] {
			continue
		}
		h := health[acct.ID]
		if h != nil && !h.IsAvailable() {
			continue
		}

		// Check budget state — skip Blocked accounts
		// StickyOnly accounts are skipped only when active sessions >= max concurrency
		if h != nil && h.budget != nil {
			state := h.budget.State()
			if state == StateBlocked {
				observe.Logger(ctx).Debug("balancer: account filtered",
					"account", acct.Name,
					"reason", state.String(),
				)
				filteredBudget++
				continue
			}
			if state == StateStickyOnly {
                activeCount := b.activeStickySessionCount(acct.ID)
                if activeCount >= acct.MaxConcurrency {
                    observe.Logger(ctx).Debug("balancer: account filtered",
                        "account", acct.Name,
                        "reason", "sticky_only at session limit",
                        "active_sessions", activeCount,
                        "max_concurrency", acct.MaxConcurrency,
                    )
                    filteredBudget++
                    continue
                }
            }
        }

		effectiveMax := acct.MaxConcurrency
		if h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, acct.MaxConcurrency)
		}
		rate := b.tracker.LoadRate(acct.ID, effectiveMax)
		if rate >= 100 {
			observe.Logger(ctx).Debug("balancer: candidate skipped (overloaded)",
				"account", acct.Name,
				"load_rate", rate,
			)
			filteredLoad++
			continue
		}
		var lu time.Time
		if v, ok := b.lastUsed.Load(acct.ID); ok {
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
		observe.Logger(ctx).Debug("balancer: no candidates after filtering",
			"total_accounts", len(accounts),
			"excluded", len(excludeAccounts),
			"filtered_budget", filteredBudget,
			"filtered_load", filteredLoad,
		)
		return nil, ErrAllAccountsBusy
	}

	// Short-circuit: single candidate, no sorting needed
	if len(candidates) == 1 {
		c := candidates[0]
		effectiveMax := c.account.MaxConcurrency
		if h := health[c.account.ID]; h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, c.account.MaxConcurrency)
		}
		if release, ok := b.tracker.Acquire(c.account.ID, requestID, effectiveMax); ok {
			b.lastUsed.Store(c.account.ID, time.Now())
			logAttrs := []any{
				"account", c.account.Name,
				"score", c.score,
				"candidates", 1,
			}
			if h := health[c.account.ID]; h != nil {
				detail := h.ScoreDetail(c.loadRate)
				logAttrs = append(logAttrs,
					"err_rate", detail.ErrRate,
					"latency_score", detail.LatencyScore,
					"load_rate", detail.LoadRate,
					"max_util", detail.MaxUtil,
				)
			}
			observe.Logger(ctx).Debug("balancer: account selected", logAttrs...)
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
		h := health[c.account.ID]
		effectiveMax := c.account.MaxConcurrency
		if h != nil {
			effectiveMax = EffectiveMaxConcurrency(h.budget, c.account.MaxConcurrency)
		}
		if release, ok := b.tracker.Acquire(c.account.ID, requestID, effectiveMax); ok {
			b.lastUsed.Store(c.account.ID, time.Now())
			// Log score breakdown for the selected account
			logAttrs := []any{
				"account", c.account.Name,
				"score", c.score,
				"candidates", len(candidates),
			}
			if h != nil {
				detail := h.ScoreDetail(c.loadRate)
				logAttrs = append(logAttrs,
					"err_rate", detail.ErrRate,
					"latency_score", detail.LatencyScore,
					"load_rate", detail.LoadRate,
					"max_util", detail.MaxUtil,
				)
			}
			observe.Logger(ctx).Debug("balancer: account selected", logAttrs...)
			return &SelectResult{Account: c.account, RequestID: requestID, Release: release}, nil
		}
	}

	return nil, ErrAllAccountsBusy
}

func (b *Balancer) findAccount(id string) *config.AccountConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, acct := range b.accounts {
		if acct.ID == id {
			found := acct
			return &found
		}
	}
	return nil
}

// BindSession creates or updates a sticky session binding.
func (b *Balancer) BindSession(sessionKey, accountID string) {
	if sessionKey == "" {
		return
	}
	b.sessions.Store(sessionKey, &SessionInfo{
		AccountID: accountID,
		LastRequest: time.Now(),
	})
	slog.Debug("session: bound", "account_id", accountID, "session_key", sessionKey)
}

// ClearSession removes a sticky session binding.
func (b *Balancer) ClearSession(sessionKey string) {
	b.sessions.Delete(sessionKey)
	slog.Debug("session: cleared", "session_key", sessionKey)
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
		if existing, ok := b.health[acct.ID]; ok {
			// Update display name in case it was renamed
			existing.Name = acct.Name
			newHealth[acct.ID] = existing
		} else {
			newHealth[acct.ID] = NewAccountHealth(acct.ID, acct.Name)
			added = append(added, acct.Name)
		}
	}
	for id := range b.health {
		if _, ok := newHealth[id]; !ok {
			removed = append(removed, id)
		}
	}
	b.health = newHealth

	// Clean up tracker entries for removed accounts
	for _, id := range removed {
		b.tracker.RemoveAccount(id)
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
func (b *Balancer) ReportResult(ctx context.Context, accountID string, statusCode int, latencyUs int64, retryAfter time.Duration, responseHeaders http.Header) {
	b.mu.RLock()
	h := b.health[accountID]
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
			go b.usageFetcher.FetchIfNeeded(context.Background(), accountID, h.budget)
		}
	} else {
		h.RecordError(ctx, statusCode, retryAfter, responseHeaders)
	}
}

// GetHealth returns the health tracker for a specific account.
func (b *Balancer) GetHealth(accountID string) *AccountHealth {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.health[accountID]
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
		id := acct.ID
		state := observe.AccountState{
			Name:           acct.Name,
			Concurrency:    b.tracker.ActiveSlots(id),
			MaxConcurrency: acct.MaxConcurrency,
		}
		if h, ok := b.health[id]; ok {
			if h.IsBanned() {
				state.Health = "banned"
			} else if h.IsDisabled() {
				state.Health = "disabled"
			} else if !h.IsAvailable() {
				state.Health = "cooldown"
			} else {
				state.Health = "healthy"
			}
			state.BudgetState = h.Budget().State().String()
		}
		states[id] = state
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

// activeStickySessionCount returns the count of active sticky sessions for an account.
// A session is considered active if it was used within the sessionTTL window.
func (b *Balancer) activeStickySessionCount(accountID string) int {
	count := 0
	b.sessions.Range(func(key, value interface{}) bool {
		info := value.(*SessionInfo)
		if info.AccountID == accountID && time.Since(info.LastRequest) < sessionTTL {
			count++
		}
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
