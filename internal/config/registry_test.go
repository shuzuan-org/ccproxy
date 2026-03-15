package config

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistryAdd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	if err := r.Add("alice"); err != nil {
		t.Fatalf("Add alice: %v", err)
	}
	if err := r.Add("bob"); err != nil {
		t.Fatalf("Add bob: %v", err)
	}

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	if list[0].Name != "alice" || list[1].Name != "bob" {
		t.Errorf("names = %v, want [alice, bob]", list)
	}
	if !list[0].Enabled || !list[1].Enabled {
		t.Error("new accounts should be enabled by default")
	}
}

func TestRegistryAdd_Duplicate(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	_ = r.Add("alice")
	err := r.Add("alice")
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestRegistryAdd_Empty(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	err := r.Add("")
	if err == nil {
		t.Fatal("expected error for empty name")
	}

	err = r.Add("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only name")
	}
}

func TestRegistryRemove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	_ = r.Add("alice")
	_ = r.Add("bob")

	if err := r.Remove("alice"); err != nil {
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

	err := r.Remove("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
}

func TestRegistryPersistence(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Create and populate
	r1 := NewAccountRegistry(dir)
	_ = r1.Add("alice")
	_ = r1.Add("bob")

	// Load from disk
	r2 := NewAccountRegistry(dir)
	list := r2.List()
	if len(list) != 2 {
		t.Fatalf("persisted len = %d, want 2", len(list))
	}
	if list[0].Name != "alice" || list[1].Name != "bob" {
		t.Errorf("persisted names = %v", list)
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

	_ = r.Add("alice")

	if !r.Has("alice") {
		t.Error("Has(alice) should be true")
	}
	if r.Has("bob") {
		t.Error("Has(bob) should be false")
	}
}

func TestRegistryNames(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	_ = r.Add("alice")
	_ = r.Add("bob")

	names := r.Names()
	if len(names) != 2 {
		t.Fatalf("names len = %d, want 2", len(names))
	}
	if names[0] != "alice" || names[1] != "bob" {
		t.Errorf("names = %v", names)
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

	_ = r.Add("alice")

	// onChange is called in a goroutine, wait briefly
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

func TestRegistryUpdateProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)
	_ = r.Add("alice")

	if err := r.UpdateProxy("alice", "socks5://10.0.0.1:1080"); err != nil {
		t.Fatalf("UpdateProxy: %v", err)
	}

	got := r.GetProxy("alice")
	if got != "socks5://10.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://10.0.0.1:1080", got)
	}

	// Verify persistence
	r2 := NewAccountRegistry(dir)
	got2 := r2.GetProxy("alice")
	if got2 != "socks5://10.0.0.1:1080" {
		t.Errorf("persisted proxy = %q", got2)
	}
}

func TestRegistryUpdateProxy_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	err := r.UpdateProxy("nonexistent", "socks5://x:1080")
	if err == nil {
		t.Fatal("expected error for nonexistent account")
	}
}

func TestRegistryGetProxy_NotFound(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	r := NewAccountRegistry(dir)

	got := r.GetProxy("nonexistent")
	if got != "" {
		t.Errorf("proxy = %q, want empty", got)
	}
}
