package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const defaultSessionTTL = 10 * time.Minute

// PKCESession stores the state of an in-progress OAuth login.
type PKCESession struct {
	InstanceName string
	Verifier     string
	State        string
	CreatedAt    time.Time
}

// SessionStore manages PKCE sessions in memory with auto-expiry.
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*PKCESession
	ttl      time.Duration
}

// NewSessionStore creates a SessionStore with default 10-minute TTL.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*PKCESession),
		ttl:      defaultSessionTTL,
	}
}

// Create starts a new PKCE session for the given instance.
// Returns the session ID and the authorization URL.
func (s *SessionStore) Create(instanceName string) (sessionID, authURL string, err error) {
	verifier := GenerateVerifier()
	challenge := GenerateChallenge(verifier)
	state := GenerateState()

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", "", err
	}
	sessionID = hex.EncodeToString(idBytes)

	provider := NewAnthropicProvider()
	authURL = provider.AuthorizationURL(state, challenge)

	s.mu.Lock()
	s.sessions[sessionID] = &PKCESession{
		InstanceName: instanceName,
		Verifier:     verifier,
		State:        state,
		CreatedAt:    time.Now(),
	}
	s.mu.Unlock()

	return sessionID, authURL, nil
}

// Get retrieves a session if it exists and is not expired.
func (s *SessionStore) Get(sessionID string) (*PKCESession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessions[sessionID]
	if !ok {
		return nil, false
	}
	if time.Since(session.CreatedAt) > s.ttl {
		return nil, false
	}
	return session, true
}

// Delete removes a session.
func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// StartCleanup runs a background goroutine that removes expired sessions.
func (s *SessionStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				for id, session := range s.sessions {
					if time.Since(session.CreatedAt) > s.ttl {
						delete(s.sessions, id)
					}
				}
				s.mu.Unlock()
			}
		}
	}()
}
