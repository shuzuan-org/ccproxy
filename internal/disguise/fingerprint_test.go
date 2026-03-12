package disguise

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFingerprintStore_GetCreatesNew(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	fp := store.Get("instance-1")
	if fp == nil {
		t.Fatal("expected non-nil fingerprint")
	}
	if fp.ClientID == "" {
		t.Error("expected non-empty ClientID")
	}
	if fp.UserAgent == "" {
		t.Error("expected non-empty UserAgent")
	}
	if fp.StainlessOS == "" {
		t.Error("expected non-empty StainlessOS")
	}
	if fp.CreatedAt == 0 {
		t.Error("expected non-zero CreatedAt")
	}

	// Verify file was persisted.
	path := filepath.Join(dir, "fingerprints.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("expected fingerprints.json to be created")
	}
}

func TestFingerprintStore_GetReturnsSame(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	fp1 := store.Get("instance-1")
	fp2 := store.Get("instance-1")

	if fp1.ClientID != fp2.ClientID {
		t.Errorf("expected same ClientID, got %q vs %q", fp1.ClientID, fp2.ClientID)
	}
	if fp1.UserAgent != fp2.UserAgent {
		t.Errorf("expected same UserAgent, got %q vs %q", fp1.UserAgent, fp2.UserAgent)
	}
}

func TestFingerprintStore_DifferentInstances(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	fp1 := store.Get("instance-1")
	fp2 := store.Get("instance-2")

	if fp1.ClientID == fp2.ClientID {
		t.Error("expected different ClientIDs for different instances")
	}
}

func TestFingerprintStore_Remove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	fp1 := store.Get("instance-1")
	if err := store.Remove("instance-1"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	fp2 := store.Get("instance-1")
	if fp1.ClientID == fp2.ClientID {
		t.Error("expected new ClientID after Remove + Get")
	}
}

func TestFingerprintStore_PersistAndReload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store1 := NewFingerprintStore(dir)
	fp1 := store1.Get("instance-1")

	// Create a new store from the same directory — should load persisted data.
	store2 := NewFingerprintStore(dir)
	fp2 := store2.Get("instance-1")

	if fp1.ClientID != fp2.ClientID {
		t.Errorf("expected same ClientID after reload, got %q vs %q", fp1.ClientID, fp2.ClientID)
	}
}

func TestFingerprintStore_Expiry(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := &FingerprintStore{
		path:         filepath.Join(dir, "fingerprints.json"),
		fingerprints: make(map[string]*Fingerprint),
		maxAge:       100 * time.Millisecond,
		renewAfter:   50 * time.Millisecond,
	}

	fp1 := store.Get("instance-1")
	clientID1 := fp1.ClientID

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	fp2 := store.Get("instance-1")
	if fp2.ClientID == clientID1 {
		t.Error("expected new fingerprint after expiry")
	}
}

func TestFingerprintStore_Renewal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := &FingerprintStore{
		path:         filepath.Join(dir, "fingerprints.json"),
		fingerprints: make(map[string]*Fingerprint),
		maxAge:       500 * time.Millisecond,
		renewAfter:   50 * time.Millisecond,
	}

	fp1 := store.Get("instance-1")
	originalUpdatedAt := fp1.UpdatedAt

	// Wait past renewAfter but before maxAge
	time.Sleep(80 * time.Millisecond)

	fp2 := store.Get("instance-1")
	// Same fingerprint but updated timestamp (millisecond precision)
	if fp2.ClientID != fp1.ClientID {
		t.Error("expected same fingerprint after renewal (not expired)")
	}
	if fp2.UpdatedAt <= originalUpdatedAt {
		t.Error("expected UpdatedAt to be refreshed after renewal")
	}
}
