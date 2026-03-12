package disguise

import (
	"context"
	"sync"
	"time"
)

type maskedSession struct {
	uuid      string
	expiresAt time.Time
}

// SessionMaskStore maps instance names to masked session UUIDs.
// Each instance gets a stable session UUID that refreshes on access
// and expires after TTL of inactivity.
type SessionMaskStore struct {
	mu       sync.Mutex
	sessions map[string]*maskedSession
	ttl      time.Duration // 15 minutes
}

// NewSessionMaskStore creates a store with 15-minute TTL.
func NewSessionMaskStore() *SessionMaskStore {
	return &SessionMaskStore{
		sessions: make(map[string]*maskedSession),
		ttl:      15 * time.Minute,
	}
}

// Get returns the masked session UUID for the given instance, creating
// one if absent or expired. Active sessions get their TTL refreshed.
func (s *SessionMaskStore) Get(instanceName string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if ms, ok := s.sessions[instanceName]; ok && now.Before(ms.expiresAt) {
		ms.expiresAt = now.Add(s.ttl)
		return ms.uuid
	}

	uuid := generateSessionUUID("")
	s.sessions[instanceName] = &maskedSession{
		uuid:      uuid,
		expiresAt: now.Add(s.ttl),
	}
	return uuid
}

// StartCleanup periodically removes expired sessions.
func (s *SessionMaskStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

func (s *SessionMaskStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for name, ms := range s.sessions {
		if now.After(ms.expiresAt) {
			delete(s.sessions, name)
		}
	}
}
