package disguise

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/fileutil"
)

// Fingerprint holds per-instance HTTP header values that distinguish one
// instance from another, preventing Anthropic from correlating them.
// Timestamps are stored in milliseconds for sub-second precision.
type Fingerprint struct {
	ClientID                string `json:"client_id"`
	UserAgent               string `json:"user_agent"`
	StainlessPackageVersion string `json:"stainless_package_version"`
	StainlessOS             string `json:"stainless_os"`
	StainlessArch           string `json:"stainless_arch"`
	StainlessRuntimeVersion string `json:"stainless_runtime_version"`
	CreatedAt               int64  `json:"created_at"`  // milliseconds
	UpdatedAt               int64  `json:"updated_at"`  // milliseconds
}

// FingerprintStore manages per-instance fingerprints with lazy renewal.
// Fingerprints are persisted to disk and expire after maxAge of inactivity.
type FingerprintStore struct {
	mu           sync.RWMutex
	path         string                  // data/fingerprints.json
	fingerprints map[string]*Fingerprint // instanceName → Fingerprint
	maxAge       time.Duration           // 7 days since last use
	renewAfter   time.Duration           // 24 hours
}

// NewFingerprintStore loads or creates a fingerprint store from disk.
func NewFingerprintStore(dataDir string) *FingerprintStore {
	s := &FingerprintStore{
		path:         filepath.Join(dataDir, "fingerprints.json"),
		fingerprints: make(map[string]*Fingerprint),
		maxAge:       7 * 24 * time.Hour,
		renewAfter:   24 * time.Hour,
	}
	s.load()
	return s
}

// Get returns the fingerprint for the given instance, creating one if needed.
// Active instances get their TTL refreshed; expired fingerprints are regenerated.
// Uses RLock fast path for fresh fingerprints to avoid write-lock contention.
func (s *FingerprintStore) Get(instanceName string) *Fingerprint {
	now := time.Now()

	// Fast path: RLock for fresh fingerprints (no disk write needed)
	s.mu.RLock()
	fp, exists := s.fingerprints[instanceName]
	if exists {
		age := now.Sub(time.UnixMilli(fp.UpdatedAt))
		if age <= s.renewAfter {
			s.mu.RUnlock()
			return fp
		}
	}
	s.mu.RUnlock()

	// Slow path: need write lock for new/expired/renewal
	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-check after acquiring write lock (another goroutine may have updated)
	fp, exists = s.fingerprints[instanceName]
	if exists {
		age := now.Sub(time.UnixMilli(fp.UpdatedAt))
		if age <= s.renewAfter {
			return fp // became fresh while waiting for lock
		}
		if age > s.maxAge {
			// Expired — regenerate
			fp = generateFingerprint(now)
			s.fingerprints[instanceName] = fp
			s.saveLocked()
		} else {
			// Renew TTL
			fp.UpdatedAt = now.UnixMilli()
			s.saveLocked()
		}
		return fp
	}

	// New instance — generate and persist
	fp = generateFingerprint(now)
	s.fingerprints[instanceName] = fp
	s.saveLocked()
	return fp
}

// Remove deletes a fingerprint for the given instance.
func (s *FingerprintStore) Remove(instanceName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.fingerprints, instanceName)
	return s.saveLocked()
}

var (
	osList   = []string{"Linux", "Darwin"}
	archList = []string{"x64", "arm64"}
)

func generateFingerprint(now time.Time) *Fingerprint {
	return &Fingerprint{
		ClientID:                GenerateClientID(),
		UserAgent:               fmt.Sprintf("claude-cli/2.1.%d (external, cli)", 20+rand.Intn(10)),
		StainlessPackageVersion: fmt.Sprintf("0.%d.%d", 69+rand.Intn(5), rand.Intn(5)),
		StainlessOS:             osList[rand.Intn(len(osList))],
		StainlessArch:           archList[rand.Intn(len(archList))],
		StainlessRuntimeVersion: fmt.Sprintf("v24.%d.0", 12+rand.Intn(4)),
		CreatedAt:               now.UnixMilli(),
		UpdatedAt:               now.UnixMilli(),
	}
}

func (s *FingerprintStore) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return // file doesn't exist yet
	}
	_ = json.Unmarshal(data, &s.fingerprints)
}

func (s *FingerprintStore) saveLocked() error {
	data, err := json.MarshalIndent(s.fingerprints, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(s.path, data, 0600)
}
