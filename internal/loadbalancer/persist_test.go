package loadbalancer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSaveAndLoadState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	health := map[string]*AccountHealth{
		"acct-a": NewAccountHealth("acct-a"),
		"acct-b": NewAccountHealth("acct-b"),
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
		"acct": NewAccountHealth("acct"),
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
		"acct-a": NewAccountHealth("acct-a"),
		"acct-b": NewAccountHealth("acct-b"),
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
