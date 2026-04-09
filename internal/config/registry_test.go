package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryAdd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id1, err := r.Add("alice", "")
	if err != nil {
		t.Fatalf("Add alice: %v", err)
	}
	id2, err := r.Add("bob", "")
	if err != nil {
		t.Fatalf("Add bob: %v", err)
	}

	if id1 == "" || id2 == "" {
		t.Fatal("returned IDs must not be empty")
	}
	if id1 == id2 {
		t.Fatal("IDs must be unique")
	}

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Name != "alice" || list[1].Name != "bob" {
		t.Errorf("names = %v, want [alice, bob]", list)
	}
	if list[0].ID != id1 || list[1].ID != id2 {
		t.Errorf("IDs mismatch")
	}
	if !list[0].Enabled || !list[1].Enabled {
		t.Error("new accounts should be enabled by default")
	}
}

func TestRegistryAdd_DuplicateNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id1, err := r.Add("alice", "user1")
	if err != nil {
		t.Fatalf("Add first alice: %v", err)
	}
	id2, err := r.Add("alice", "user2")
	if err != nil {
		t.Fatalf("Add second alice: %v", err)
	}

	if id1 == id2 {
		t.Fatal("duplicate names must get different IDs")
	}
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
}

func TestRegistryAdd_Empty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	_, err := r.Add("", "")
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	_, err = r.Add("   ", "")
	if err == nil {
		t.Fatal("expected error for whitespace-only name")
	}
}

func TestRegistryRemove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id1, _ := r.Add("alice", "")
	r.Add("bob", "")

	if err := r.Remove(id1); err != nil {
		t.Fatalf("Remove alice: %v", err)
	}

	list := r.List()
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	if list[0].Name != "bob" {
		t.Errorf("remaining name = %q, want bob", list[0].Name)
	}
}

func TestRegistryRemove_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	err := r.Remove("nonexistent-id")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
}

func TestRegistryPersistence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create and populate
	r1 := NewAccountRegistry(dir)
	id1, _ := r1.Add("alice", "")
	id2, _ := r1.Add("bob", "")

	// Load from disk
	r2 := NewAccountRegistry(dir)
	list := r2.List()
	if len(list) != 2 {
		t.Fatalf("persisted len = %d, want 2", len(list))
	}
	if list[0].Name != "alice" || list[1].Name != "bob" {
		t.Errorf("persisted names = %v", list)
	}
	if list[0].ID != id1 || list[1].ID != id2 {
		t.Errorf("persisted IDs mismatch")
	}

	// Verify file permissions
	info, err := os.Stat(filepath.Join(dir, "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file permissions = %o, want 600", info.Mode().Perm())
	}
}

func TestRegistryHas(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id, _ := r.Add("alice", "")

	if !r.Has(id) {
		t.Error("Has(id) should be true")
	}
	if r.Has("nonexistent") {
		t.Error("Has(nonexistent) should be false")
	}
}

func TestRegistryNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	r.Add("alice", "")
	r.Add("bob", "")

	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("names len = %d, want 2", len(names))
	}
	if names[0] != "alice" || names[1] != "bob" {
		t.Errorf("names = %v", names)
	}
}

func TestRegistryIDs(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id1, _ := r.Add("alice", "")
	id2, _ := r.Add("bob", "")

	ids := r.IDs()
	if len(ids) != 2 {
		t.Fatalf("ids len = %d, want 2", len(ids))
	}
	if ids[0] != id1 || ids[1] != id2 {
		t.Errorf("ids = %v", ids)
	}
}

func TestRegistryGetByID(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id, _ := r.Add("alice", "owner1")

	acct, ok := r.GetByID(id)
	if !ok {
		t.Fatal("GetByID should return true for existing ID")
	}
	if acct.Name != "alice" || acct.Owner != "owner1" {
		t.Errorf("got %+v", acct)
	}

	_, ok = r.GetByID("nonexistent")
	if ok {
		t.Error("GetByID should return false for nonexistent ID")
	}
}

func TestRegistryRename(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id, _ := r.Add("alice", "")

	if err := r.Rename(id, "alice-renamed"); err != nil {
		t.Fatalf("Rename: %v", err)
	}

	acct, _ := r.GetByID(id)
	if acct.Name != "alice-renamed" {
		t.Errorf("name = %q, want alice-renamed", acct.Name)
	}

	// Verify persistence
	r2 := NewAccountRegistry(dir)
	acct2, _ := r2.GetByID(id)
	if acct2.Name != "alice-renamed" {
		t.Errorf("persisted name = %q", acct2.Name)
	}
}

func TestRegistryRename_Empty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id, _ := r.Add("alice", "")

	if err := r.Rename(id, ""); err == nil {
		t.Fatal("expected error for empty name")
	}
	if err := r.Rename(id, "  "); err == nil {
		t.Fatal("expected error for whitespace name")
	}
}

func TestRegistryRename_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	if err := r.Rename("nonexistent", "newname"); err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
}

func TestRegistryOnChange(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	var called atomic.Int32
	r.SetOnChange(func(accounts []Account) {
		called.Add(1)
	})

	r.Add("alice", "")

	// onChange is called via channel consumer goroutine, wait briefly
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if called.Load() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if called.Load() == 0 {
		t.Error("onChange was not called after Add")
	}
}

func TestRegistryOnChange_Serialized(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	var lastSnapshot atomic.Value // stores []Account
	var callCount atomic.Int32

	r.SetOnChange(func(accounts []Account) {
		// Simulate slow consumer to expose ordering issues
		time.Sleep(10 * time.Millisecond)
		cp := make([]Account, len(accounts))
		copy(cp, accounts)
		lastSnapshot.Store(cp)
		callCount.Add(1)
	})

	// Rapid-fire adds
	for i := 0; i < 5; i++ {
		if _, err := r.Add(fmt.Sprintf("acct-%d", i), ""); err != nil {
			t.Fatalf("Add acct-%d: %v", i, err)
		}
	}

	// Wait for consumer to finish processing
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if callCount.Load() > 0 {
			// Give the consumer time to process any remaining items
			time.Sleep(50 * time.Millisecond)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for any in-flight processing to complete
	time.Sleep(100 * time.Millisecond)

	snap := lastSnapshot.Load()
	if snap == nil {
		t.Fatal("onChange was never called")
	}

	accounts := snap.([]Account)
	// The last snapshot received must contain all 5 accounts
	if len(accounts) != 5 {
		t.Errorf("final snapshot has %d accounts, want 5", len(accounts))
	}
}

func TestRegistryUpdateProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)
	id, _ := r.Add("alice", "")

	if err := r.UpdateProxy(id, "socks5://10.0.0.1:1080"); err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}

	got := r.GetProxy(id)
	if got != "socks5://10.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://10.0.0.1:1080", got)
	}

	// Verify persistence
	r2 := NewAccountRegistry(dir)
	list := r2.List()
	got2 := r2.GetProxy(list[0].ID)
	if got2 != "socks5://10.0.0.1:1080" {
		t.Errorf("persisted proxy = %q", got2)
	}
}

func TestRegistryUpdateProxy_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	err := r.UpdateProxy("nonexistent-id", "socks5://x:1080")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
}

func TestRegistryGetProxy_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	got := r.GetProxy("nonexistent-id")
	if got != "" {
		t.Errorf("proxy = %q, want empty", got)
	}
}

func TestRegistryAutoMigration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write old-format accounts without IDs
	oldData := `[{"name":"alice","enabled":true,"owner":"user1"},{"name":"bob","enabled":true}]`
	if err := os.WriteFile(filepath.Join(dir, "accounts.json"), []byte(oldData), 0o600); err != nil {
		t.Fatal(err)
	}

	r := NewAccountRegistry(dir)
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}

	// Verify UUIDs were assigned
	for _, acct := range list {
		if acct.ID == "" {
			t.Errorf("account %q should have a generated ID", acct.Name)
		}
		// UUID format: 8-4-4-4-12
		parts := strings.Split(acct.ID, "-")
		if len(parts) != 5 {
			t.Errorf("account %q has invalid UUID: %s", acct.Name, acct.ID)
		}
	}

	if list[0].ID == list[1].ID {
		t.Error("migrated accounts should have different UUIDs")
	}

	// Verify UUIDs are persisted
	raw, _ := os.ReadFile(filepath.Join(dir, "accounts.json"))
	var persisted []Account
	json.Unmarshal(raw, &persisted)
	if persisted[0].ID == "" || persisted[1].ID == "" {
		t.Error("UUIDs should be persisted to disk")
	}
}

func TestRegistryNameToIDMap(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	id1, _ := r.Add("alice", "")
	id2, _ := r.Add("bob", "")

	m := r.NameToIDMap()
	if m["alice"] != id1 {
		t.Errorf("alice ID = %q, want %q", m["alice"], id1)
	}
	if m["bob"] != id2 {
		t.Errorf("bob ID = %q, want %q", m["bob"], id2)
	}
}
