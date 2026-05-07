package disguise

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/binn/ccproxy/internal/fileutil"
)

// Fingerprint holds per-account HTTP header values that distinguish one
// account from another, preventing Anthropic from correlating them.
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

// FingerprintStore manages per-account fingerprints with lazy renewal.
// Fingerprints are persisted to disk and expire after maxAge of inactivity.
type FingerprintStore struct {
	mu           sync.RWMutex
	path         string                  // data/fingerprints.json
	fingerprints map[string]*Fingerprint // accountName → Fingerprint
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
	s.rebaseToDefaults()
	return s
}

// Get returns the fingerprint for the given account, creating one if needed.
// Active accounts get their TTL refreshed; expired fingerprints are regenerated.
// Uses RLock fast path for fresh fingerprints to avoid write-lock contention.
func (s *FingerprintStore) Get(accountName string) *Fingerprint {
	now := time.Now()

	// Fast path: RLock for fresh fingerprints (no disk write needed)
	s.mu.RLock()
	fp, exists := s.fingerprints[accountName]
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
	fp, exists = s.fingerprints[accountName]
	if exists {
		age := now.Sub(time.UnixMilli(fp.UpdatedAt))
		if age <= s.renewAfter {
			return fp // became fresh while waiting for lock
		}
		if age > s.maxAge {
			// Expired — regenerate
			fp = generateFingerprint(now)
			s.fingerprints[accountName] = fp
			_ = s.saveLocked()
			slog.Debug("disguise/fingerprint: expired, regenerated",
				"account", accountName,
				"age", age.String(),
				"ua", fp.UserAgent,
			)
		} else {
			// Renew TTL
			fp.UpdatedAt = now.UnixMilli()
			_ = s.saveLocked()
			slog.Debug("disguise/fingerprint: TTL renewed",
				"account", accountName,
				"age", age.String(),
			)
		}
		return fp
	}

	// New account — generate and persist
	fp = generateFingerprint(now)
	s.fingerprints[accountName] = fp
	_ = s.saveLocked()
	slog.Debug("disguise/fingerprint: created for new account",
		"account", accountName,
		"ua", fp.UserAgent,
		"os", fp.StainlessOS,
		"arch", fp.StainlessArch,
	)
	return fp
}

// Remove deletes a fingerprint for the given account.
func (s *FingerprintStore) Remove(accountName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.fingerprints, accountName)
	return s.saveLocked()
}

// MigrateKeys re-keys the fingerprint store from old account names to UUIDs.
func (s *FingerprintStore) MigrateKeys(nameToID map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	migrated := false
	for key, fp := range s.fingerprints {
		if id, ok := nameToID[key]; ok && id != key {
			s.fingerprints[id] = fp
			delete(s.fingerprints, key)
			migrated = true
		}
	}
	if migrated {
		if err := s.saveLocked(); err != nil {
			slog.Warn("fingerprints: failed to persist key migration", "error", err.Error())
		} else {
			slog.Info("fingerprints: migrated keys to UUIDs", "count", len(nameToID))
		}
	}
}

func generateFingerprint(now time.Time) *Fingerprint {
	return &Fingerprint{
		ClientID:                GenerateClientID(),
		UserAgent:               DefaultHeaders["User-Agent"],
		StainlessPackageVersion: DefaultHeaders["X-Stainless-Package-Version"],
		StainlessOS:             DefaultHeaders["X-Stainless-OS"],
		StainlessArch:           DefaultHeaders["X-Stainless-Arch"],
		StainlessRuntimeVersion: DefaultHeaders["X-Stainless-Runtime-Version"],
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

// rebaseToWhitelist forces every persisted fingerprint's CLI tuple
// (UA, StainlessPackageVersion, StainlessRuntimeVersion) onto the
// current whitelist head. Historical fingerprints captured before the
// cch-attestation rollout may carry arbitrary client-reported values;
// after this rollout we own that tuple unconditionally so cch + 3hex
// stay verifiable against ATTEST_KEYS.
//
// Per-account OS/Arch are preserved — those reflect the client machine,
// not the CLI release, and have no interaction with cch.
//
// Runs at startup, after load(), without holding the public lock (the
// store is not yet shared).
func (s *FingerprintStore) rebaseToDefaults() {
	tuple := latestValidatedTuple()
	now := time.Now().UnixMilli()
	changed := false
	for name, fp := range s.fingerprints {
		if fp == nil {
			continue
		}
		if fp.UserAgent == tuple.UserAgent &&
			fp.StainlessPackageVersion == tuple.StainlessPackageVersion &&
			fp.StainlessRuntimeVersion == tuple.StainlessRuntimeVersion {
			continue
		}
		oldUA := fp.UserAgent
		fp.UserAgent = tuple.UserAgent
		fp.StainlessPackageVersion = tuple.StainlessPackageVersion
		fp.StainlessRuntimeVersion = tuple.StainlessRuntimeVersion
		fp.UpdatedAt = now
		changed = true
		slog.Debug("disguise/fingerprint: rebased to whitelist head on load",
			"account", name,
			"old_ua", oldUA,
			"new_ua", fp.UserAgent,
		)
	}
	if changed {
		_ = s.saveLocked()
	}
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

// LearnFromHeaders updates the fingerprint for an account based on headers
// observed from a real Claude Code client.
//
// As of cch-attestation rollout (2026-05) the CLI tuple (UA, SDK, Runtime)
// is NOT learned from the client — it is locked to the latest entry in
// version_whitelist.go. We only adopt machine-level attributes (OS, Arch)
// from the client headers, since those are independent of the CLI release
// and have no interaction with cch verification.
func (s *FingerprintStore) LearnFromHeaders(accountName string, headers http.Header) {
	if headers.Get("User-Agent") == "" {
		return
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	fp, exists := s.fingerprints[accountName]
	if !exists {
		// No fingerprint yet — create with whitelist tuple + observed
		// machine attributes.
		fp = createFromHeaders(headers, now)
		s.fingerprints[accountName] = fp
		_ = s.saveLocked()
		slog.Debug("disguise/fingerprint: learned from CC client (new)",
			"account", accountName,
			"ua", fp.UserAgent,
			"os", fp.StainlessOS,
			"arch", fp.StainlessArch,
		)
		return
	}

	// Re-pin the CLI tuple to the current whitelist head — this lets
	// long-lived accounts pick up whitelist bumps after a ccproxy upgrade
	// without manual reset. Cheap idempotent assignment when nothing
	// changed.
	oldUA := fp.UserAgent
	mergeClientTuple(fp, headers)
	mergeClientMachine(fp, headers)
	fp.UpdatedAt = now.UnixMilli()
	_ = s.saveLocked()

	if oldUA != fp.UserAgent {
		slog.Debug("disguise/fingerprint: tuple bumped to current whitelist",
			"account", accountName,
			"old_ua", oldUA,
			"new_ua", fp.UserAgent,
		)
	}
}

// createFromHeaders builds a Fingerprint from observed request headers,
// using defaults for any missing values.
//
// If the observed User-Agent is older than DefaultHeaders["User-Agent"], the
// default is used instead. Otherwise a new account created by an old client
// would be permanently pinned to that old version, even though newer clients
// exist — sabotaging the whole point of keeping defaults current.
//
// The (UA, Stainless Package Version, Runtime Version) triple is a tightly
// coupled tuple: each Claude CLI release bundles one specific combination.
// As of cch-attestation rollout (2026-05) we keep this triple under our own
// control rather than mirroring the client — it must stay in lockstep with
// the ATTEST_KEYS in cch.go (which only verify against a known-good range
// of CLI binaries). See version_whitelist.go for the source of truth.
//
// Adopting client-side values for UA/SDK/Runtime would risk forwarding a
// version whose cch keys we have not extracted, producing wire bytes that
// the server cannot verify. OS and Arch describe the client machine and
// have no interaction with cch — those we still adopt freely.
func createFromHeaders(headers http.Header, now time.Time) *Fingerprint {
	tuple := latestValidatedTuple()
	fp := &Fingerprint{
		ClientID:                GenerateClientID(),
		UserAgent:               tuple.UserAgent,
		StainlessPackageVersion: tuple.StainlessPackageVersion,
		StainlessRuntimeVersion: tuple.StainlessRuntimeVersion,
		CreatedAt:               now.UnixMilli(),
		UpdatedAt:               now.UnixMilli(),
	}

	if v := headers.Get("X-Stainless-OS"); v != "" {
		fp.StainlessOS = v
	} else {
		fp.StainlessOS = DefaultHeaders["X-Stainless-OS"]
	}

	if v := headers.Get("X-Stainless-Arch"); v != "" {
		fp.StainlessArch = v
	} else {
		fp.StainlessArch = DefaultHeaders["X-Stainless-Arch"]
	}

	return fp
}

// mergeClientTuple is a no-op for the CLI release triple — see the
// rationale on createFromHeaders. We only refresh UA/SDK/Runtime when the
// validated whitelist itself rolls forward (a code change), never from
// observed client traffic. This function exists solely to update the
// fingerprint to whatever the current whitelist head is, which lets a
// long-lived account pick up whitelist bumps without manual reset.
func mergeClientTuple(fp *Fingerprint, _ http.Header) {
	tuple := latestValidatedTuple()
	fp.UserAgent = tuple.UserAgent
	fp.StainlessPackageVersion = tuple.StainlessPackageVersion
	fp.StainlessRuntimeVersion = tuple.StainlessRuntimeVersion
}

// mergeClientMachine updates the machine-level fields (OS and Arch). These
// reflect the client's operating system and CPU architecture, not the CLI
// release, so they are adopted independently of the CLI version tuple.
func mergeClientMachine(fp *Fingerprint, headers http.Header) {
	if v := headers.Get("X-Stainless-OS"); v != "" {
		fp.StainlessOS = v
	}
	if v := headers.Get("X-Stainless-Arch"); v != "" {
		fp.StainlessArch = v
	}
}

// semver holds a parsed semantic version.
type semver struct {
	major, minor, patch int
	valid               bool
}

// extractVersionFromUA extracts the version string from a User-Agent like
// "claude-cli/2.1.22 (external, cli)" and parses it as semver.
func extractVersionFromUA(ua string) semver {
	// Find "claude-cli/" prefix
	idx := strings.Index(ua, "claude-cli/")
	if idx < 0 {
		return semver{}
	}
	rest := ua[idx+len("claude-cli/"):]
	// Take until space or end
	if sp := strings.IndexByte(rest, ' '); sp >= 0 {
		rest = rest[:sp]
	}
	return parseVersion(rest)
}

// parseVersion parses a "major.minor.patch" string into semver.
func parseVersion(s string) semver {
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return semver{}
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	patch, err3 := strconv.Atoi(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return semver{}
	}
	return semver{major: major, minor: minor, patch: patch, valid: true}
}

// isNewerVersion returns true if a is strictly newer than b.
func isNewerVersion(a, b semver) bool {
	if !a.valid || !b.valid {
		return a.valid // if a is valid but b isn't, treat a as newer
	}
	if a.major != b.major {
		return a.major > b.major
	}
	if a.minor != b.minor {
		return a.minor > b.minor
	}
	return a.patch > b.patch
}
