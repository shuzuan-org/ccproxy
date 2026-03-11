package oauth

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()

	sessionID, authURL, err := ss.Create("alice-oauth")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sessionID == "" {
		t.Fatal("empty session ID")
	}
	if !strings.Contains(authURL, "claude.ai/oauth/authorize") {
		t.Errorf("authURL missing authorize endpoint: %s", authURL)
	}
	if !strings.Contains(authURL, ClientID) {
		t.Errorf("authURL missing client_id: %s", authURL)
	}

	session, ok := ss.Get(sessionID)
	if !ok {
		t.Fatal("session not found after Create")
	}
	if session.InstanceName != "alice-oauth" {
		t.Errorf("instance = %q, want alice-oauth", session.InstanceName)
	}
	if session.Verifier == "" {
		t.Error("empty verifier")
	}
	if session.State == "" {
		t.Error("empty state")
	}
}

func TestSessionStore_GetExpired(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()
	ss.ttl = 1 * time.Millisecond

	sessionID, _, err := ss.Create("bob-oauth")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	time.Sleep(5 * time.Millisecond)

	_, ok := ss.Get(sessionID)
	if ok {
		t.Error("expected expired session to not be found")
	}
}

func TestSessionStore_Delete(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()

	sessionID, _, _ := ss.Create("test-oauth")
	ss.Delete(sessionID)

	_, ok := ss.Get(sessionID)
	if ok {
		t.Error("session still found after Delete")
	}
}

func TestSessionStore_Cleanup(t *testing.T) {
	t.Parallel()
	ss := NewSessionStore()
	ss.ttl = 1 * time.Millisecond

	ss.Create("a")
	ss.Create("b")

	time.Sleep(5 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ss.StartCleanup(ctx, 10*time.Millisecond)

	time.Sleep(50 * time.Millisecond)

	ss.mu.RLock()
	count := len(ss.sessions)
	ss.mu.RUnlock()

	if count != 0 {
		t.Errorf("expected 0 sessions after cleanup, got %d", count)
	}
}
