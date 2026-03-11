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
		"inst-a": NewAccountHealth("inst-a", 7, 10),
		"inst-b": NewAccountHealth("inst-b", 3, 10),
	}
	health["inst-b"].Disable("forbidden")

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

	a := state.Accounts["inst-a"]
	if a.MaxConcurrency != 7 {
		t.Errorf("inst-a: expected maxConcurrency 7, got %d", a.MaxConcurrency)
	}
	if a.Disabled {
		t.Error("inst-a should not be disabled")
	}

	b := state.Accounts["inst-b"]
	if !b.Disabled {
		t.Error("inst-b should be disabled")
	}
	if b.DisabledReason != "forbidden" {
		t.Errorf("inst-b: expected reason 'forbidden', got %q", b.DisabledReason)
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
		"inst": NewAccountHealth("inst", 5, 10),
	}
	if err := SaveState(dir, health); err != nil {
		t.Fatalf("SaveState failed: %v", err)
	}

	// Backdate the file's modification time by 25 hours won't work;
	// instead, read, modify updated_at, and rewrite.
	path := filepath.Join(dir, stateFileName)
	data, _ := os.ReadFile(path)

	// Replace updated_at with a stale time (crude but effective)
	staleTime := time.Now().Add(-25 * time.Hour)
	_ = os.WriteFile(path, data, statePerm)

	// Actually we need to modify the JSON content. Let's just write a stale state directly.
	staleState := `{"accounts":{"inst":{"max_concurrency":5}},"updated_at":"` +
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
		"inst-a": NewAccountHealth("inst-a", 5, 10),
		"inst-b": NewAccountHealth("inst-b", 5, 10),
	}

	state := &PersistedState{
		Accounts: map[string]*PersistedAccount{
			"inst-a": {MaxConcurrency: 8, Disabled: false},
			"inst-b": {MaxConcurrency: 3, Disabled: true, DisabledReason: "forbidden"},
			"inst-c": {MaxConcurrency: 5}, // not in health map — should be ignored
		},
		UpdatedAt: time.Now(),
	}

	ApplyState(health, state)

	if health["inst-a"].MaxConcurrency() != 8 {
		t.Errorf("inst-a: expected maxConcurrency 8, got %d", health["inst-a"].MaxConcurrency())
	}
	if health["inst-b"].MaxConcurrency() != 3 {
		t.Errorf("inst-b: expected maxConcurrency 3, got %d", health["inst-b"].MaxConcurrency())
	}
	if !health["inst-b"].IsDisabled() {
		t.Error("inst-b should be disabled after apply")
	}
}
