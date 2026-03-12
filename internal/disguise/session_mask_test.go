package disguise

import (
	"sync"
	"testing"
	"time"
)

func TestSessionMaskStore_GetCreatesNew(t *testing.T) {
	t.Parallel()
	store := NewSessionMaskStore()

	uuid := store.Get("instance-1")
	if uuid == "" {
		t.Error("expected non-empty UUID")
	}
}

func TestSessionMaskStore_GetReturnsSame(t *testing.T) {
	t.Parallel()
	store := NewSessionMaskStore()

	uuid1 := store.Get("instance-1")
	uuid2 := store.Get("instance-1")

	if uuid1 != uuid2 {
		t.Errorf("expected same UUID within TTL, got %q vs %q", uuid1, uuid2)
	}
}

func TestSessionMaskStore_DifferentInstances(t *testing.T) {
	t.Parallel()
	store := NewSessionMaskStore()

	uuid1 := store.Get("instance-1")
	uuid2 := store.Get("instance-2")

	if uuid1 == uuid2 {
		t.Error("expected different UUIDs for different instances")
	}
}

func TestSessionMaskStore_Expiry(t *testing.T) {
	t.Parallel()
	store := &SessionMaskStore{
		sessions: make(map[string]*maskedSession),
		ttl:      50 * time.Millisecond,
	}

	uuid1 := store.Get("instance-1")
	time.Sleep(80 * time.Millisecond)
	uuid2 := store.Get("instance-1")

	if uuid1 == uuid2 {
		t.Error("expected different UUID after expiry")
	}
}

func TestSessionMaskStore_TTLRefresh(t *testing.T) {
	t.Parallel()
	store := &SessionMaskStore{
		sessions: make(map[string]*maskedSession),
		ttl:      100 * time.Millisecond,
	}

	uuid1 := store.Get("instance-1")

	// Access at 60ms (within TTL) — should refresh
	time.Sleep(60 * time.Millisecond)
	uuid2 := store.Get("instance-1")
	if uuid1 != uuid2 {
		t.Error("expected same UUID after refresh within TTL")
	}

	// Access at another 60ms (120ms total, but TTL was refreshed at 60ms)
	time.Sleep(60 * time.Millisecond)
	uuid3 := store.Get("instance-1")
	if uuid1 != uuid3 {
		t.Error("expected same UUID: TTL was refreshed at 60ms, so still valid at 120ms")
	}
}

func TestSessionMaskStore_Concurrent(t *testing.T) {
	t.Parallel()
	store := NewSessionMaskStore()

	var wg sync.WaitGroup
	results := make([]string, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = store.Get("instance-1")
		}(i)
	}
	wg.Wait()

	// All results should be the same UUID
	first := results[0]
	for i, r := range results {
		if r != first {
			t.Errorf("result[%d] = %q, expected %q", i, r, first)
		}
	}
}
