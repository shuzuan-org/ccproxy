package config

import (
	"fmt"
	"sort"
	"strings"
)

// ResolvedScope describes which accounts an API key may dispatch to.
// A nil or AllowAll scope short-circuits any per-account filtering.
type ResolvedScope struct {
	AllowAll      bool            // "*" was present
	AllowUnowned  bool            // "unowned" was present
	AllowedOwners map[string]bool // expanded from "self", "owner:*", "pool:*"
}

// Contains reports whether the given account owner is in scope.
// A nil receiver means "no filter" — the zero-config, fully-backwards-compatible behaviour.
func (s *ResolvedScope) Contains(owner string) bool {
	if s == nil || s.AllowAll {
		return true
	}
	if owner == "" {
		return s.AllowUnowned
	}
	return s.AllowedOwners[owner]
}

// Signature returns a deterministic fingerprint of the scope so that
// API keys with equivalent scopes can be bucketed together (used by
// the admin dashboard's grouping view).
func (s *ResolvedScope) Signature() string {
	if s == nil || s.AllowAll {
		return "*"
	}
	owners := make([]string, 0, len(s.AllowedOwners))
	for o := range s.AllowedOwners {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	sig := strings.Join(owners, ",")
	if s.AllowUnowned {
		sig += "|unowned"
	}
	if sig == "" {
		sig = "(empty)"
	}
	return sig
}

// SortedOwners returns the allowed owners in deterministic order.
func (s *ResolvedScope) SortedOwners() []string {
	if s == nil {
		return nil
	}
	owners := make([]string, 0, len(s.AllowedOwners))
	for o := range s.AllowedOwners {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	return owners
}

// ResolveScheduling expands a scheduling directive list into a ResolvedScope.
// Unknown entries produce an error. Unknown pool references produce an error
// (the referenced pool must exist). References to usernames that do not yet
// exist are allowed — they simply resolve to the literal owner name.
func ResolveScheduling(apiKeyName string, scheduling []string, pools []PoolConfig) (*ResolvedScope, error) {
	// Empty/unset defaults to "*" (global pool, backwards compatible).
	if len(scheduling) == 0 {
		return &ResolvedScope{AllowAll: true}, nil
	}

	poolIndex := make(map[string]*PoolConfig, len(pools))
	for i := range pools {
		poolIndex[pools[i].Name] = &pools[i]
	}

	scope := &ResolvedScope{AllowedOwners: map[string]bool{}}
	for _, raw := range scheduling {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		switch {
		case entry == "*":
			return &ResolvedScope{AllowAll: true}, nil
		case entry == "unowned":
			scope.AllowUnowned = true
		case entry == "self":
			scope.AllowedOwners[apiKeyName] = true
		case strings.HasPrefix(entry, "owner:"):
			owner := strings.TrimSpace(strings.TrimPrefix(entry, "owner:"))
			if owner == "" {
				return nil, fmt.Errorf("api_key %q: empty owner in scheduling entry %q", apiKeyName, raw)
			}
			scope.AllowedOwners[owner] = true
		case strings.HasPrefix(entry, "pool:"):
			poolName := strings.TrimSpace(strings.TrimPrefix(entry, "pool:"))
			if poolName == "" {
				return nil, fmt.Errorf("api_key %q: empty pool name in scheduling entry %q", apiKeyName, raw)
			}
			pool, ok := poolIndex[poolName]
			if !ok {
				return nil, fmt.Errorf("api_key %q: scheduling references unknown pool %q", apiKeyName, poolName)
			}
			for _, m := range pool.Members {
				m = strings.TrimSpace(m)
				if m == "" {
					continue
				}
				scope.AllowedOwners[m] = true
			}
		default:
			return nil, fmt.Errorf("api_key %q: unknown scheduling entry %q (expected self, owner:<name>, pool:<name>, *, unowned)", apiKeyName, raw)
		}
	}

	return scope, nil
}

// BuildSchedulingScopes returns a map of api_key_name -> ResolvedScope for
// every configured API key. It is cheap and cached by the caller at startup.
// Errors in individual entries fail fast, bubbled up from ResolveScheduling.
func (c *Config) BuildSchedulingScopes() (map[string]*ResolvedScope, error) {
	out := make(map[string]*ResolvedScope, len(c.APIKeys))
	for _, k := range c.APIKeys {
		if k.Name == "" {
			continue
		}
		scope, err := ResolveScheduling(k.Name, k.Scheduling, c.Pools)
		if err != nil {
			return nil, err
		}
		out[k.Name] = scope
	}
	return out, nil
}
