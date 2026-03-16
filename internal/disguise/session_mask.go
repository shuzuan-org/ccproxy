package disguise

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type maskedSession struct {
	uuid      string
	expiresAt time.Time
}

// SessionMaskStore maps account names to masked session UUIDs.
// Each account gets a stable session UUID that refreshes on access
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

// Get returns the masked session UUID for the given account, creating
// one if absent or expired. Active sessions get their TTL refreshed.
func (s *SessionMaskStore) Get(accountName string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	if ms, ok := s.sessions[accountName]; ok && now.Before(ms.expiresAt) {
		ms.expiresAt = now.Add(s.ttl)
		return ms.uuid
	}

	uuid := generateSessionUUID("")
	s.sessions[accountName] = &maskedSession{
		uuid:      uuid,
		expiresAt: now.Add(s.ttl),
	}
	slog.Debug("disguise/session_mask: created new mask",
		"account", accountName,
		"mask_uuid", uuid[:8]+"...",
		"ttl", s.ttl.String(),
	)
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
	expired := 0
	for name, ms := range s.sessions {
		if now.After(ms.expiresAt) {
			delete(s.sessions, name)
			expired++
		}
	}
	if expired > 0 {
		slog.Debug("disguise/session_mask: cleanup expired masks",
			"expired", expired,
			"remaining", len(s.sessions),
		)
	}
}
