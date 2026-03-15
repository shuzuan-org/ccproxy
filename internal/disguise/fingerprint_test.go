package disguise

import (
	"net/http"
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

func TestParseVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  semver
	}{
		{"2.1.22", semver{2, 1, 22, true}},
		{"0.70.0", semver{0, 70, 0, true}},
		{"invalid", semver{}},
		{"1.2", semver{}},
		{"a.b.c", semver{}},
	}
	for _, tc := range tests {
		got := parseVersion(tc.input)
		if got != tc.want {
			t.Errorf("parseVersion(%q) = %+v, want %+v", tc.input, got, tc.want)
		}
	}
}

func TestIsNewerVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b semver
		want bool
	}{
		{semver{2, 2, 0, true}, semver{2, 1, 22, true}, true},
		{semver{2, 1, 23, true}, semver{2, 1, 22, true}, true},
		{semver{2, 1, 22, true}, semver{2, 1, 22, true}, false},
		{semver{2, 1, 21, true}, semver{2, 1, 22, true}, false},
		{semver{3, 0, 0, true}, semver{2, 99, 99, true}, true},
		{semver{valid: true}, semver{}, true},   // valid > invalid
		{semver{}, semver{valid: true}, false},   // invalid < valid
	}
	for _, tc := range tests {
		got := isNewerVersion(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("isNewerVersion(%+v, %+v) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestExtractVersionFromUA(t *testing.T) {
	t.Parallel()
	tests := []struct {
		ua   string
		want semver
	}{
		{"claude-cli/2.1.22 (external, cli)", semver{2, 1, 22, true}},
		{"claude-cli/3.0.0", semver{3, 0, 0, true}},
		{"curl/7.88.1", semver{}},
		{"", semver{}},
	}
	for _, tc := range tests {
		got := extractVersionFromUA(tc.ua)
		if got != tc.want {
			t.Errorf("extractVersionFromUA(%q) = %+v, want %+v", tc.ua, got, tc.want)
		}
	}
}

func TestLearnFromHeaders_NewInstance(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.2.0 (external, cli)")
	headers.Set("X-Stainless-Package-Version", "0.72.0")
	headers.Set("X-Stainless-OS", "Darwin")
	headers.Set("X-Stainless-Arch", "arm64")
	headers.Set("X-Stainless-Runtime-Version", "v24.14.0")

	store.LearnFromHeaders("inst-new", headers)

	fp := store.Get("inst-new")
	if fp.UserAgent != "claude-cli/2.2.0 (external, cli)" {
		t.Errorf("expected learned UA, got %q", fp.UserAgent)
	}
	if fp.StainlessPackageVersion != "0.72.0" {
		t.Errorf("expected learned package version, got %q", fp.StainlessPackageVersion)
	}
	if fp.StainlessOS != "Darwin" {
		t.Errorf("expected learned OS, got %q", fp.StainlessOS)
	}
}

func TestLearnFromHeaders_NewerVersionMerge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	// First learn with older version
	h1 := http.Header{}
	h1.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
	h1.Set("X-Stainless-OS", "Linux")
	store.LearnFromHeaders("inst-1", h1)

	fp1 := store.Get("inst-1")
	if fp1.UserAgent != "claude-cli/2.1.22 (external, cli)" {
		t.Fatalf("initial UA mismatch: %q", fp1.UserAgent)
	}

	// Learn with newer version → should merge
	h2 := http.Header{}
	h2.Set("User-Agent", "claude-cli/2.2.0 (external, cli)")
	h2.Set("X-Stainless-OS", "Darwin")
	store.LearnFromHeaders("inst-1", h2)

	fp2 := store.Get("inst-1")
	if fp2.UserAgent != "claude-cli/2.2.0 (external, cli)" {
		t.Errorf("expected merged newer UA, got %q", fp2.UserAgent)
	}
	if fp2.StainlessOS != "Darwin" {
		t.Errorf("expected merged OS, got %q", fp2.StainlessOS)
	}
}

func TestLearnFromHeaders_OlderVersionNoMerge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	// First learn with newer version
	h1 := http.Header{}
	h1.Set("User-Agent", "claude-cli/2.2.0 (external, cli)")
	h1.Set("X-Stainless-OS", "Darwin")
	store.LearnFromHeaders("inst-1", h1)

	// Learn with older version → should NOT merge (only refresh TTL)
	h2 := http.Header{}
	h2.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
	h2.Set("X-Stainless-OS", "Linux")
	store.LearnFromHeaders("inst-1", h2)

	fp := store.Get("inst-1")
	if fp.UserAgent != "claude-cli/2.2.0 (external, cli)" {
		t.Errorf("expected UA unchanged (older version), got %q", fp.UserAgent)
	}
	if fp.StainlessOS != "Darwin" {
		t.Errorf("expected OS unchanged (older version), got %q", fp.StainlessOS)
	}
}
