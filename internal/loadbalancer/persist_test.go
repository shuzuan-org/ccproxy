package loadbalancer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/binn/ccproxy/internal/config"
)

func TestSaveAndLoadState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	health := map[string]*AccountHealth{
		"acct-a": NewAccountHealth("acct-a-id", "acct-a"),
		"acct-b": NewAccountHealth("acct-b-id", "acct-b"),
	}
	health["acct-b"].Disable("forbidden")

	if err := SaveState(dir, health); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	state := LoadState(dir)
	if state == nil {
		t.Fatal("LoadState returned nil")
	}
	if len(state.Accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %d", len(state.Accounts))
	}

	a := state.Accounts["acct-a"]
	if a.Disabled {
		t.Error("acct-a should not be disabled")
	}

	b := state.Accounts["acct-b"]
	if !b.Disabled {
		t.Error("acct-b should be disabled")
	}
	if b.DisabledReason != "forbidden" {
		t.Errorf("acct-b: expected reason 'forbidden', got %q", b.DisabledReason)
	}
}

func TestLoadState_MissingFile(t *testing.T) {
	t.Parallel()
	state := LoadState(t.TempDir())
	if state != nil {
		t.Error("expected nil for missing file")
	}
}

func TestLoadState_StaleFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	health := map[string]*AccountHealth{
		"acct": NewAccountHealth("acct-id", "acct"),
	}
	if err := SaveState(dir, health); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Write a stale state directly
	path := filepath.Join(dir, stateFileName)
	staleTime := time.Now().Add(-25 * time.Hour)
	staleState := `{"accounts":{"acct":{"disabled":false}},"updated_at":"` +
		staleTime.Format(time.RFC3339) + `"}`
	_ = os.WriteFile(path, []byte(staleState), statePerm)

	state := LoadState(dir)
	if state != nil {
		t.Error("expected nil for stale file")
	}
}

func TestApplyState_RestoresValues(t *testing.T) {
	t.Parallel()

	health := map[string]*AccountHealth{
		"acct-a": NewAccountHealth("acct-a-id", "acct-a"),
		"acct-b": NewAccountHealth("acct-b-id", "acct-b"),
	}

	state := &PersistedState{
		Accounts: map[string]*PersistedAccount{
			"acct-a": {Disabled: false},
			"acct-b": {Disabled: true, DisabledReason: "forbidden"},
			"acct-c": {Disabled: false}, // not in health map — should be ignored
		},
		UpdatedAt: time.Now(),
	}

	ApplyState(health, state)

	if health["acct-a"].IsDisabled() {
		t.Error("acct-a should not be disabled")
	}
	if !health["acct-b"].IsDisabled() {
		t.Error("acct-b should be disabled after apply")
	}
}

func TestMigrateHealthStateKeys(t *testing.T) {
	t.Parallel()

	state := &PersistedState{
		Accounts: map[string]*PersistedAccount{
			"alice": {Disabled: true, DisabledReason: "banned"},
			"bob":   {Disabled: false},
		},
		UpdatedAt: time.Now(),
	}

	nameToID := map[string]string{
		"alice": "uuid-alice",
		"bob":   "uuid-bob",
	}

	migrated := MigrateHealthStateKeys(state, nameToID)
	if !migrated {
		t.Fatal("expected migration to occur")
	}

	if _, ok := state.Accounts["alice"]; ok {
		t.Error("old key 'alice' should be removed")
	}
	if _, ok := state.Accounts["bob"]; ok {
		t.Error("old key 'bob' should be removed")
	}

	a := state.Accounts["uuid-alice"]
	if a == nil || !a.Disabled || a.DisabledReason != "banned" {
		t.Errorf("alice state not preserved: %+v", a)
	}
	b := state.Accounts["uuid-bob"]
	if b == nil || b.Disabled {
		t.Errorf("bob state not preserved: %+v", b)
	}
}

func TestMigrateHealthStateKeys_AlreadyMigrated(t *testing.T) {
	t.Parallel()

	state := &PersistedState{
		Accounts: map[string]*PersistedAccount{
			"uuid-alice": {Disabled: true},
		},
		UpdatedAt: time.Now(),
	}

	// nameToID maps name→uuid, but state already uses uuid keys
	nameToID := map[string]string{"alice": "uuid-alice"}

	migrated := MigrateHealthStateKeys(state, nameToID)
	if migrated {
		t.Error("should not migrate when keys are already UUIDs")
	}
}

func TestBalancer_LoadState_WithMigration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Save state with old name-based keys
	oldHealth := map[string]*AccountHealth{
		"old-name": NewAccountHealth("old-name", "old-name"),
	}
	oldHealth["old-name"].Disable("test-reason")
	if err := SaveState(dir, oldHealth); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	// Create balancer with UUID-based accounts
	accounts := []config.AccountConfig{
		{ID: "new-uuid", Name: "old-name", MaxConcurrency: 5, Enabled: true},
	}
	b := NewBalancer(accounts, NewConcurrencyTracker())

	// Load with migration map
	b.LoadState(dir, map[string]string{"old-name": "new-uuid"})

	h := b.GetHealth("new-uuid")
	if h == nil {
		t.Fatal("expected health for new-uuid")
	}
	if !h.IsDisabled() {
		t.Error("disabled state should be preserved after migration")
	}
}
