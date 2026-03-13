package oauth

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *TokenStore {
	t.Helper()
	dir := t.TempDir()
	store, err := NewTokenStore(dir)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	return store
}

func TestStore_SaveLoad(t *testing.T) {
	store := newTestStore(t)
	token := OAuthToken{
		AccessToken:  "access-abc",
		RefreshToken: "refresh-xyz",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
		Scope:        "user:inference",
	}
	if err := store.Save("anthropic", token); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := store.Load("anthropic")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil token")
	}
	if loaded.AccessToken != token.AccessToken {
		t.Errorf("AccessToken mismatch: got %q, want %q", loaded.AccessToken, token.AccessToken)
	}
	if loaded.RefreshToken != token.RefreshToken {
		t.Errorf("RefreshToken mismatch: got %q, want %q", loaded.RefreshToken, token.RefreshToken)
	}
	if loaded.Scope != token.Scope {
		t.Errorf("Scope mismatch: got %q, want %q", loaded.Scope, token.Scope)
	}
}

func TestStore_FileIsEncrypted(t *testing.T) {
	dir := t.TempDir()
	store, err := NewTokenStore(dir)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	token := OAuthToken{
		AccessToken:  "super-secret-token",
		RefreshToken: "super-secret-refresh",
		ExpiresAt:    time.Now().Add(time.Hour),
		Scope:        "user:inference",
	}
	if err := store.Save("anthropic", token); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Read raw file bytes
	raw, err := os.ReadFile(filepath.Join(dir, "oauth_tokens.json"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// The access token plaintext must NOT appear in the file
	if bytes.Contains(raw, []byte("super-secret-token")) {
		t.Error("file contains plaintext access_token — should be encrypted")
	}
}

func TestStore_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewTokenStore(dir)
	if err != nil {
		t.Fatalf("NewTokenStore: %v", err)
	}
	token := OAuthToken{
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := store.Save("provider", token); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "oauth_tokens.json"))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected file permissions 0600, got %04o", perm)
	}
}

func TestStore_MultipleProviders(t *testing.T) {
	store := newTestStore(t)
	t1 := OAuthToken{AccessToken: "tok-a", ExpiresAt: time.Now().Add(time.Hour)}
	t2 := OAuthToken{AccessToken: "tok-b", ExpiresAt: time.Now().Add(time.Hour)}

	if err := store.Save("provider-a", t1); err != nil {
		t.Fatalf("Save provider-a: %v", err)
	}
	if err := store.Save("provider-b", t2); err != nil {
		t.Fatalf("Save provider-b: %v", err)
	}

	la, err := store.Load("provider-a")
	if err != nil || la == nil || la.AccessToken != "tok-a" {
		t.Errorf("provider-a: got %v, err %v", la, err)
	}
	lb, err := store.Load("provider-b")
	if err != nil || lb == nil || lb.AccessToken != "tok-b" {
		t.Errorf("provider-b: got %v, err %v", lb, err)
	}
}

func TestStore_Delete(t *testing.T) {
	store := newTestStore(t)
	token := OAuthToken{AccessToken: "tok", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Save("p", token); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.Delete("p"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	loaded, err := store.Load("p")
	if err != nil {
		t.Fatalf("Load after delete: %v", err)
	}
	if loaded != nil {
		t.Error("expected nil token after delete")
	}
}

func TestStore_LoadNonexistent(t *testing.T) {
	store := newTestStore(t)
	loaded, err := store.Load("no-such-provider")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if loaded != nil {
		t.Errorf("expected nil, got %+v", loaded)
	}
}

func TestStore_List(t *testing.T) {
	store := newTestStore(t)
	providers := []string{"alpha", "beta", "gamma"}
	for _, p := range providers {
		tok := OAuthToken{AccessToken: "tok-" + p, ExpiresAt: time.Now().Add(time.Hour)}
		if err := store.Save(p, tok); err != nil {
			t.Fatalf("Save %s: %v", p, err)
		}
	}
	listed := store.List()
	sort.Strings(listed)
	sort.Strings(providers)
	if len(listed) != len(providers) {
		t.Fatalf("expected %d providers, got %d: %v", len(providers), len(listed), listed)
	}
	for i, name := range providers {
		if listed[i] != name {
			t.Errorf("listed[%d] = %q, want %q", i, listed[i], name)
		}
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	key1, err := deriveKey()
	if err != nil {
		t.Fatalf("deriveKey() error: %v", err)
	}
	key2, err := deriveKey()
	if err != nil {
		t.Fatalf("deriveKey() second call error: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Error("deriveKey() should return deterministic results")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(key1))
	}
}

func TestMachineID_NotPanic(t *testing.T) {
	// machineID() should never panic regardless of platform
	id := machineID()
	// On macOS/Linux it should return a non-empty string; on other platforms empty is fine
	_ = id
}
