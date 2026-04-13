package config

import (
	"reflect"
	"testing"
)

func TestResolveScheduling(t *testing.T) {
	pools := []PoolConfig{
		{Name: "team-a", Members: []string{"alice", "bob", "charlie"}},
		{Name: "singleton", Members: []string{"dave"}},
	}

	tests := []struct {
		name       string
		apiKeyName string
		scheduling []string
		wantAll    bool
		wantUnowned bool
		wantOwners []string
		wantErr    bool
	}{
		{
			name:       "empty defaults to AllowAll",
			apiKeyName: "alice",
			scheduling: nil,
			wantAll:    true,
		},
		{
			name:       "explicit wildcard",
			apiKeyName: "alice",
			scheduling: []string{"*"},
			wantAll:    true,
		},
		{
			name:       "wildcard with other entries short-circuits",
			apiKeyName: "alice",
			scheduling: []string{"self", "owner:bob", "*"},
			wantAll:    true,
		},
		{
			name:       "self only",
			apiKeyName: "alice",
			scheduling: []string{"self"},
			wantOwners: []string{"alice"},
		},
		{
			name:       "owner prefix",
			apiKeyName: "alice",
			scheduling: []string{"owner:bob", "owner:charlie"},
			wantOwners: []string{"bob", "charlie"},
		},
		{
			name:       "pool expansion",
			apiKeyName: "alice",
			scheduling: []string{"pool:team-a"},
			wantOwners: []string{"alice", "bob", "charlie"},
		},
		{
			name:       "mixed self + owner + pool dedupes",
			apiKeyName: "alice",
			scheduling: []string{"self", "owner:dave", "pool:team-a"},
			wantOwners: []string{"alice", "bob", "charlie", "dave"},
		},
		{
			name:        "unowned flag",
			apiKeyName:  "alice",
			scheduling:  []string{"self", "unowned"},
			wantOwners:  []string{"alice"},
			wantUnowned: true,
		},
		{
			name:       "unknown pool errors",
			apiKeyName: "alice",
			scheduling: []string{"pool:missing"},
			wantErr:    true,
		},
		{
			name:       "unknown prefix errors",
			apiKeyName: "alice",
			scheduling: []string{"group:team-a"},
			wantErr:    true,
		},
		{
			name:       "empty owner value errors",
			apiKeyName: "alice",
			scheduling: []string{"owner:"},
			wantErr:    true,
		},
		{
			name:       "empty pool value errors",
			apiKeyName: "alice",
			scheduling: []string{"pool:"},
			wantErr:    true,
		},
		{
			name:       "whitespace tolerated",
			apiKeyName: "alice",
			scheduling: []string{"  self ", " owner:bob "},
			wantOwners: []string{"alice", "bob"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope, err := ResolveScheduling(tt.apiKeyName, tt.scheduling, pools)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if scope.AllowAll != tt.wantAll {
				t.Errorf("AllowAll = %v, want %v", scope.AllowAll, tt.wantAll)
			}
			if scope.AllowUnowned != tt.wantUnowned {
				t.Errorf("AllowUnowned = %v, want %v", scope.AllowUnowned, tt.wantUnowned)
			}
			if !tt.wantAll {
				got := scope.SortedOwners()
				if !reflect.DeepEqual(got, tt.wantOwners) {
					t.Errorf("SortedOwners = %v, want %v", got, tt.wantOwners)
				}
			}
		})
	}
}

func TestResolvedScope_Contains(t *testing.T) {
	t.Run("nil scope allows everything", func(t *testing.T) {
		var s *ResolvedScope
		if !s.Contains("alice") || !s.Contains("") {
			t.Fatal("nil scope must allow all owners")
		}
	})

	t.Run("AllowAll allows everything", func(t *testing.T) {
		s := &ResolvedScope{AllowAll: true}
		if !s.Contains("alice") || !s.Contains("") {
			t.Fatal("AllowAll must allow all owners")
		}
	})

	t.Run("owner set excludes others", func(t *testing.T) {
		s := &ResolvedScope{AllowedOwners: map[string]bool{"alice": true}}
		if !s.Contains("alice") {
			t.Error("alice should be in scope")
		}
		if s.Contains("bob") {
			t.Error("bob should not be in scope")
		}
		if s.Contains("") {
			t.Error("empty owner should not be in scope without AllowUnowned")
		}
	})

	t.Run("AllowUnowned gates empty owner", func(t *testing.T) {
		s := &ResolvedScope{AllowedOwners: map[string]bool{}, AllowUnowned: true}
		if !s.Contains("") {
			t.Error("empty owner should be in scope with AllowUnowned")
		}
		if s.Contains("alice") {
			t.Error("alice should not be in scope")
		}
	})
}

func TestResolvedScope_Signature(t *testing.T) {
	tests := []struct {
		name  string
		scope *ResolvedScope
		want  string
	}{
		{"nil is wildcard", nil, "*"},
		{"AllowAll is wildcard", &ResolvedScope{AllowAll: true}, "*"},
		{"single owner", &ResolvedScope{AllowedOwners: map[string]bool{"alice": true}}, "alice"},
		{"multi owner sorted", &ResolvedScope{AllowedOwners: map[string]bool{"bob": true, "alice": true}}, "alice,bob"},
		{"with unowned suffix", &ResolvedScope{AllowedOwners: map[string]bool{"alice": true}, AllowUnowned: true}, "alice|unowned"},
		{"empty scope", &ResolvedScope{AllowedOwners: map[string]bool{}}, "(empty)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.scope.Signature(); got != tt.want {
				t.Errorf("Signature() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSchedulingScopes(t *testing.T) {
	cfg := &Config{
		APIKeys: []APIKeyConfig{
			{Name: "alice"},
			{Name: "bob", Scheduling: []string{"self"}},
			{Name: "charlie", Scheduling: []string{"pool:team-a"}},
			{Name: ""}, // ignored
		},
		Pools: []PoolConfig{
			{Name: "team-a", Members: []string{"alice", "bob"}},
		},
	}

	scopes, err := cfg.BuildSchedulingScopes()
	if err != nil {
		t.Fatalf("BuildSchedulingScopes failed: %v", err)
	}

	if len(scopes) != 3 {
		t.Errorf("expected 3 scopes, got %d", len(scopes))
	}
	if !scopes["alice"].AllowAll {
		t.Error("alice should default to AllowAll")
	}
	if scopes["bob"].AllowAll {
		t.Error("bob should be restricted to self")
	}
	if !scopes["bob"].AllowedOwners["bob"] {
		t.Error("bob should allow self")
	}
	if !scopes["charlie"].AllowedOwners["alice"] || !scopes["charlie"].AllowedOwners["bob"] {
		t.Error("charlie should inherit team-a pool members")
	}
}

func TestBuildSchedulingScopes_PropagatesErrors(t *testing.T) {
	cfg := &Config{
		APIKeys: []APIKeyConfig{
			{Name: "alice", Scheduling: []string{"pool:missing"}},
		},
	}
	_, err := cfg.BuildSchedulingScopes()
	if err == nil {
		t.Fatal("expected error for unknown pool reference")
	}
}
