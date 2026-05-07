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

	fp := store.Get("account-1")
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

	fp1 := store.Get("account-1")
	fp2 := store.Get("account-1")

	if fp1.ClientID != fp2.ClientID {
		t.Errorf("expected same ClientID, got %q vs %q", fp1.ClientID, fp2.ClientID)
	}
	if fp1.UserAgent != fp2.UserAgent {
		t.Errorf("expected same UserAgent, got %q vs %q", fp1.UserAgent, fp2.UserAgent)
	}
}

func TestFingerprintStore_DifferentAccounts(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	fp1 := store.Get("account-1")
	fp2 := store.Get("account-2")

	if fp1.ClientID == fp2.ClientID {
		t.Error("expected different ClientIDs for different accounts")
	}
}

func TestFingerprintStore_Remove(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	fp1 := store.Get("account-1")
	if err := store.Remove("account-1"); err != nil {
		t.Fatalf("remove: %v", err)
	}

	fp2 := store.Get("account-1")
	if fp1.ClientID == fp2.ClientID {
		t.Error("expected new ClientID after Remove + Get")
	}
}

func TestFingerprintStore_PersistAndReload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store1 := NewFingerprintStore(dir)
	fp1 := store1.Get("account-1")

	// Create a new store from the same directory — should load persisted data.
	store2 := NewFingerprintStore(dir)
	fp2 := store2.Get("account-1")

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

	fp1 := store.Get("account-1")
	clientID1 := fp1.ClientID

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	fp2 := store.Get("account-1")
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

	fp1 := store.Get("account-1")
	originalUpdatedAt := fp1.UpdatedAt

	// Wait past renewAfter but before maxAge
	time.Sleep(80 * time.Millisecond)

	fp2 := store.Get("account-1")
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

func TestLearnFromHeaders_NewAccount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	// As of cch-attestation rollout, the CLI tuple (UA, SDK, Runtime)
	// is locked to the whitelist regardless of what the client reports.
	// Only OS/Arch (machine attributes) are adopted from the client.
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.2.0 (external, cli)")
	headers.Set("X-Stainless-Package-Version", "0.72.0")
	headers.Set("X-Stainless-OS", "MacOS")
	headers.Set("X-Stainless-Arch", "arm64")
	headers.Set("X-Stainless-Runtime-Version", "v24.14.0")

	store.LearnFromHeaders("acct-new", headers)

	fp := store.Get("acct-new")
	tuple := latestValidatedTuple()
	if fp.UserAgent != tuple.UserAgent {
		t.Errorf("expected whitelist UA %q, got %q", tuple.UserAgent, fp.UserAgent)
	}
	if fp.StainlessPackageVersion != tuple.StainlessPackageVersion {
		t.Errorf("expected whitelist package version %q, got %q",
			tuple.StainlessPackageVersion, fp.StainlessPackageVersion)
	}
	if fp.StainlessOS != "MacOS" {
		t.Errorf("expected learned OS, got %q", fp.StainlessOS)
	}
}

// TestLearnFromHeaders_NewerClientStillPinned verifies that even when the
// client reports a CLI version newer than the whitelist head, ccproxy
// stays on the validated tuple — we never forward an unvalidated cc_version
// because cch verification depends on ATTEST_KEYS being valid for that
// version. OS/Arch still adopt the client's machine.
func TestLearnFromHeaders_NewerClientStillPinned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	// Seed account with an initial learn.
	h1 := http.Header{}
	h1.Set("User-Agent", "claude-cli/2.1.126 (external, cli)")
	h1.Set("X-Stainless-Package-Version", "0.81.0")
	h1.Set("X-Stainless-Runtime-Version", "v24.3.0")
	h1.Set("X-Stainless-OS", "Linux")
	store.LearnFromHeaders("acct-1", h1)

	// Client reports a hypothetically newer version we haven't validated
	// yet. CLI tuple must NOT adopt; only OS updates.
	h2 := http.Header{}
	h2.Set("User-Agent", "claude-cli/3.0.0 (external, cli)")
	h2.Set("X-Stainless-Package-Version", "0.99.0")
	h2.Set("X-Stainless-Runtime-Version", "v25.0.0")
	h2.Set("X-Stainless-OS", "MacOS")
	store.LearnFromHeaders("acct-1", h2)

	fp := store.Get("acct-1")
	tuple := latestValidatedTuple()
	if fp.UserAgent != tuple.UserAgent {
		t.Errorf("UA must stay on whitelist head, got %q", fp.UserAgent)
	}
	if fp.StainlessPackageVersion != tuple.StainlessPackageVersion {
		t.Errorf("PackageVersion must stay on whitelist head, got %q", fp.StainlessPackageVersion)
	}
	if fp.StainlessRuntimeVersion != tuple.StainlessRuntimeVersion {
		t.Errorf("RuntimeVersion must stay on whitelist head, got %q", fp.StainlessRuntimeVersion)
	}
	if fp.StainlessOS != "MacOS" {
		t.Errorf("OS should track latest client machine, got %q", fp.StainlessOS)
	}
}

// TestLearnFromHeaders_PartialTupleStillPinned: the client may legitimately
// omit some Stainless headers — that does not affect us, since we ignore
// the client's CLI tuple anyway. UA/SDK/Runtime stay locked.
func TestLearnFromHeaders_PartialTupleStillPinned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	// Seed with a complete-tuple learn.
	h1 := http.Header{}
	h1.Set("User-Agent", "claude-cli/2.1.126 (external, cli)")
	h1.Set("X-Stainless-Package-Version", "0.81.0")
	h1.Set("X-Stainless-Runtime-Version", "v24.3.0")
	h1.Set("X-Stainless-OS", "Linux")
	store.LearnFromHeaders("acct-1", h1)

	// Subsequent request omits SDK/Runtime headers entirely.
	h2 := http.Header{}
	h2.Set("User-Agent", "claude-cli/9.9.9 (external, cli)")
	h2.Set("X-Stainless-OS", "MacOS")
	store.LearnFromHeaders("acct-1", h2)

	fp := store.Get("acct-1")
	tuple := latestValidatedTuple()
	if fp.UserAgent != tuple.UserAgent {
		t.Errorf("UA should remain on whitelist head, got %q", fp.UserAgent)
	}
	if fp.StainlessPackageVersion != tuple.StainlessPackageVersion {
		t.Errorf("PackageVersion should remain on whitelist head, got %q", fp.StainlessPackageVersion)
	}
	if fp.StainlessRuntimeVersion != tuple.StainlessRuntimeVersion {
		t.Errorf("RuntimeVersion should remain on whitelist head, got %q", fp.StainlessRuntimeVersion)
	}
	if fp.StainlessOS != "MacOS" {
		t.Errorf("OS should still update independently, got %q", fp.StainlessOS)
	}
}

// TestLearnFromHeaders_OlderClientStillPinned: same as the newer-client
// case but the other direction — old clients (e.g. 2.1.22) cannot drag
// the tuple backward either.
func TestLearnFromHeaders_OlderClientStillPinned(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	store := NewFingerprintStore(dir)

	// Seed with whitelist-head client.
	h1 := http.Header{}
	h1.Set("User-Agent", "claude-cli/2.1.126 (external, cli)")
	h1.Set("X-Stainless-Package-Version", "0.81.0")
	h1.Set("X-Stainless-Runtime-Version", "v24.3.0")
	h1.Set("X-Stainless-OS", "MacOS")
	store.LearnFromHeaders("acct-1", h1)

	// Older-version client follows; tuple must not be downgraded; OS
	// reflects the new machine.
	h2 := http.Header{}
	h2.Set("User-Agent", "claude-cli/2.1.22 (external, cli)")
	h2.Set("X-Stainless-Package-Version", "0.60.0")
	h2.Set("X-Stainless-Runtime-Version", "v20.0.0")
	h2.Set("X-Stainless-OS", "Linux")
	store.LearnFromHeaders("acct-1", h2)

	fp := store.Get("acct-1")
	tuple := latestValidatedTuple()
	if fp.UserAgent != tuple.UserAgent {
		t.Errorf("UA must stay on whitelist head, got %q", fp.UserAgent)
	}
	if fp.StainlessPackageVersion != tuple.StainlessPackageVersion {
		t.Errorf("PackageVersion must stay on whitelist head, got %q", fp.StainlessPackageVersion)
	}
	if fp.StainlessRuntimeVersion != tuple.StainlessRuntimeVersion {
		t.Errorf("RuntimeVersion must stay on whitelist head, got %q", fp.StainlessRuntimeVersion)
	}
	if fp.StainlessOS != "Linux" {
		t.Errorf("OS should track latest client machine, got %q", fp.StainlessOS)
	}
}
