# Disguise Chain Sub2api Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align ccproxy's disguise chain with sub2api across three gaps: metadata.user_id JSON format (CLI ≥ 2.1.78), empty text block cleanup after thinking conversion, and system prompt prefix list sync.

**Architecture:** All changes are in-place modifications to existing files. The largest change is in `metadata.go` / `engine.go` (new format support), the others are small targeted fixes. Each task is independently testable with existing test infrastructure.

**Tech Stack:** Go 1.25, `encoding/json`, `regexp`, `fmt`, `strings`

---

## File Map

| File | Change |
|------|--------|
| `internal/disguise/metadata.go` | Add `ParsedUserID`, `ParseUserID`, `userIDJSON`, version helpers; update `GenerateUserID` and `RewriteUserIDWithMasking` and `RewriteUserID` signatures; refactor `injectMetadataUserIDInPlace` |
| `internal/disguise/metadata_test.go` | New test cases for JSON format |
| `internal/disguise/detector.go` | Change `detectorRequest.Metadata.UserID` from `string` to `json.RawMessage`; add `validUserIDRaw`; update signal 3; update prefix list |
| `internal/disguise/detector_test.go` | New test for JSON format user_id detection |
| `internal/disguise/engine.go` | Extract UA version; pass `uaVersion` to user_id functions; update `injectMetadataUserIDInPlace` call |
| `internal/proxy/bodyfilter.go` | Add `stripEmptyTextBlocks`; call it in `filterBlocks` |
| `internal/proxy/bodyfilter_test.go` | New test cases for empty text block stripping |

---

## Task 1: Add ParsedUserID, ParseUserID, version helpers to metadata.go

**Files:**
- Modify: `internal/disguise/metadata.go`
- Test: `internal/disguise/metadata_test.go`

These are pure additions — no existing function signatures change yet. The new symbols are used in later tasks.

- [ ] **Step 1: Write the failing tests**

Append to `internal/disguise/metadata_test.go`:

```go
// --- ParseUserID tests ---

func TestParseUserID_OldFormatA(t *testing.T) {
	t.Parallel()
	raw := "user_" + strings.Repeat("ab", 32) + "_account__session_abc-123-def"
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID for format A")
	}
	if p.DeviceID != strings.Repeat("ab", 32) {
		t.Errorf("unexpected DeviceID: %q", p.DeviceID)
	}
	if p.SessionID != "abc-123-def" {
		t.Errorf("unexpected SessionID: %q", p.SessionID)
	}
	if p.IsNewFormat {
		t.Error("expected IsNewFormat=false for old format A")
	}
}

func TestParseUserID_OldFormatB(t *testing.T) {
	t.Parallel()
	raw := "user_" + strings.Repeat("cd", 32) + "_account_acc-uuid_session_sess-uuid"
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID for format B")
	}
	if p.AccountUUID != "acc-uuid" {
		t.Errorf("unexpected AccountUUID: %q", p.AccountUUID)
	}
}

func TestParseUserID_NewJSONFormat(t *testing.T) {
	t.Parallel()
	raw := `{"device_id":"` + strings.Repeat("ab", 32) + `","account_uuid":"acc-uuid","session_id":"sess-uuid"}`
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID for JSON format")
	}
	if !p.IsNewFormat {
		t.Error("expected IsNewFormat=true")
	}
	if p.DeviceID != strings.Repeat("ab", 32) {
		t.Errorf("unexpected DeviceID: %q", p.DeviceID)
	}
	if p.SessionID != "sess-uuid" {
		t.Errorf("unexpected SessionID: %q", p.SessionID)
	}
	if p.AccountUUID != "acc-uuid" {
		t.Errorf("unexpected AccountUUID: %q", p.AccountUUID)
	}
}

func TestParseUserID_NewJSONFormat_NoAccountUUID(t *testing.T) {
	t.Parallel()
	raw := `{"device_id":"` + strings.Repeat("ef", 32) + `","session_id":"sess-abc"}`
	p := ParseUserID(raw)
	if p == nil {
		t.Fatal("expected non-nil ParsedUserID")
	}
	if p.AccountUUID != "" {
		t.Errorf("expected empty AccountUUID, got %q", p.AccountUUID)
	}
}

func TestParseUserID_Invalid(t *testing.T) {
	t.Parallel()
	if ParseUserID("random-garbage") != nil {
		t.Error("expected nil for unrecognized format")
	}
	if ParseUserID("") != nil {
		t.Error("expected nil for empty string")
	}
}

func TestParseUserID_JSONMissingDeviceID(t *testing.T) {
	t.Parallel()
	raw := `{"session_id":"sess-uuid"}`
	if ParseUserID(raw) != nil {
		t.Error("expected nil when device_id missing")
	}
}

// --- compareVersions tests ---

func TestCompareVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want int
	}{
		{"2.1.78", "2.1.78", 0},
		{"2.1.79", "2.1.78", 1},
		{"2.1.77", "2.1.78", -1},
		{"2.2.0", "2.1.78", 1},
		{"3.0.0", "2.1.78", 1},
		{"1.9.99", "2.0.0", -1},
	}
	for _, tt := range tests {
		got := compareVersions(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/binn/ZedProjects/token-run-workspace/ccproxy
go test ./internal/disguise/... -run "TestParseUserID|TestCompareVersions" -v 2>&1 | head -30
```

Expected: `undefined: ParseUserID`, `undefined: compareVersions`

- [ ] **Step 3: Add to metadata.go**

Add these imports to `metadata.go` (add `encoding/json`, `strconv`, `strings` — check existing imports first and only add missing ones):

```go
import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)
```

Then add after the existing `var userIDFormatA/B` declarations:

```go
// NewMetadataFormatMinVersion is the minimum Claude CLI version that uses the
// JSON object format for metadata.user_id instead of the legacy string format.
const NewMetadataFormatMinVersion = "2.1.78"

// userIDJSON is the new metadata.user_id format used by Claude CLI >= 2.1.78.
type userIDJSON struct {
	DeviceID    string `json:"device_id"`
	AccountUUID string `json:"account_uuid,omitempty"`
	SessionID   string `json:"session_id"`
}

// ParsedUserID holds the decoded fields from either metadata.user_id format.
type ParsedUserID struct {
	DeviceID    string
	AccountUUID string // empty when absent
	SessionID   string
	IsNewFormat bool // true if the original was JSON object format
}

// ParseUserID parses both the legacy string format and the new JSON object format.
// Returns nil when the input does not match either known format.
func ParseUserID(rawID string) *ParsedUserID {
	rawID = strings.TrimSpace(rawID)
	if rawID == "" {
		return nil
	}
	// New format: JSON object {"device_id":"...","session_id":"..."}
	if strings.HasPrefix(rawID, "{") {
		var obj userIDJSON
		if err := json.Unmarshal([]byte(rawID), &obj); err == nil && obj.DeviceID != "" && obj.SessionID != "" {
			return &ParsedUserID{
				DeviceID:    obj.DeviceID,
				AccountUUID: obj.AccountUUID,
				SessionID:   obj.SessionID,
				IsNewFormat: true,
			}
		}
		return nil
	}
	// Legacy format A: user_{64hex}_account__session_{uuid}
	if m := userIDFormatA.FindStringSubmatch(rawID); m != nil {
		return &ParsedUserID{DeviceID: m[1], SessionID: m[2]}
	}
	// Legacy format B: user_{64hex}_account_{uuid}_session_{uuid}
	if m := userIDFormatB.FindStringSubmatch(rawID); m != nil {
		return &ParsedUserID{DeviceID: m[1], AccountUUID: m[2], SessionID: m[3]}
	}
	return nil
}

// compareVersions compares two semver strings of the form "X.Y.Z".
// Returns -1, 0, or 1 like strings.Compare.
func compareVersions(a, b string) int {
	partsA := strings.SplitN(a, ".", 3)
	partsB := strings.SplitN(b, ".", 3)
	for i := 0; i < 3; i++ {
		var na, nb int
		if i < len(partsA) {
			na, _ = strconv.Atoi(partsA[i])
		}
		if i < len(partsB) {
			nb, _ = strconv.Atoi(partsB[i])
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

// isNewMetadataFormatVersion returns true when uaVersion >= NewMetadataFormatMinVersion.
func isNewMetadataFormatVersion(uaVersion string) bool {
	if uaVersion == "" {
		return false
	}
	return compareVersions(uaVersion, NewMetadataFormatMinVersion) >= 0
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/disguise/... -run "TestParseUserID|TestCompareVersions" -v 2>&1 | tail -20
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/disguise/metadata.go internal/disguise/metadata_test.go
git commit -m "feat(disguise): add ParsedUserID, ParseUserID, version helpers for CLI>=2.1.78"
```

---

## Task 2: Update GenerateUserID and RewriteUserIDWithMasking for JSON format

**Files:**
- Modify: `internal/disguise/metadata.go`
- Test: `internal/disguise/metadata_test.go`

Changes function signatures — callers in `engine.go` will break until Task 3.

- [ ] **Step 1: Write the failing tests**

Append to `internal/disguise/metadata_test.go`:

```go
// --- GenerateUserID with uaVersion ---

func TestGenerateUserID_OldFormat_LowVersion(t *testing.T) {
	t.Parallel()
	uid := GenerateUserID("seed", "2.1.22")
	if !userIDPattern.MatchString(uid) {
		t.Errorf("expected old string format for version 2.1.22, got %q", uid)
	}
}

func TestGenerateUserID_OldFormat_EmptyVersion(t *testing.T) {
	t.Parallel()
	uid := GenerateUserID("seed", "")
	if !userIDPattern.MatchString(uid) {
		t.Errorf("expected old string format for empty version, got %q", uid)
	}
}

func TestGenerateUserID_NewFormat_HighVersion(t *testing.T) {
	t.Parallel()
	uid := GenerateUserID("seed", "2.1.78")
	if !strings.HasPrefix(uid, "{") {
		t.Errorf("expected JSON format for version 2.1.78, got %q", uid)
	}
	p := ParseUserID(uid)
	if p == nil || !p.IsNewFormat {
		t.Errorf("expected parseable JSON format, got %q", uid)
	}
}

func TestGenerateUserID_NewFormat_Deterministic(t *testing.T) {
	t.Parallel()
	uid1 := GenerateUserID("seed-x", "2.1.78")
	uid2 := GenerateUserID("seed-x", "2.1.78")
	if uid1 != uid2 {
		t.Errorf("expected deterministic output, got %q vs %q", uid1, uid2)
	}
}

// --- RewriteUserIDWithMasking with uaVersion ---

func TestRewriteUserIDWithMasking_OldFormatA_PreservesFormat(t *testing.T) {
	t.Parallel()
	original := "user_" + strings.Repeat("ab", 32) + "_account__session_old-sess"
	result := RewriteUserIDWithMasking(original, "seed", "masked-uuid", "2.1.22")
	if !strings.Contains(result, "masked-uuid") {
		t.Errorf("expected masked UUID in result, got %q", result)
	}
	if strings.HasPrefix(result, "{") {
		t.Errorf("expected old string format, got JSON: %q", result)
	}
}

func TestRewriteUserIDWithMasking_NewFormatInput_OutputsJSON(t *testing.T) {
	t.Parallel()
	original := `{"device_id":"` + strings.Repeat("ab", 32) + `","session_id":"old-sess"}`
	result := RewriteUserIDWithMasking(original, "seed", "masked-uuid", "2.1.78")
	if !strings.HasPrefix(result, "{") {
		t.Errorf("expected JSON output for JSON input, got %q", result)
	}
	p := ParseUserID(result)
	if p == nil || p.SessionID != "masked-uuid" {
		t.Errorf("expected session_id=masked-uuid in result, got %q", result)
	}
}

func TestRewriteUserIDWithMasking_OldInputHighVersion_OutputsJSON(t *testing.T) {
	t.Parallel()
	// When uaVersion says new format but input is old, still output JSON (version takes precedence)
	original := "user_" + strings.Repeat("ab", 32) + "_account__session_old-sess"
	result := RewriteUserIDWithMasking(original, "seed", "masked-uuid", "2.1.78")
	if !strings.HasPrefix(result, "{") {
		t.Errorf("expected JSON output for high version, got %q", result)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/disguise/... -run "TestGenerateUserID_OldFormat_LowVersion|TestGenerateUserID_NewFormat|TestRewriteUserIDWithMasking_NewFormat|TestRewriteUserIDWithMasking_OldInput" -v 2>&1 | head -20
```

Expected: compile error because signatures don't match yet.

- [ ] **Step 3: Update GenerateUserID in metadata.go**

Replace the existing `GenerateUserID` function:

```go
// GenerateUserID creates a metadata.user_id value.
// For uaVersion >= 2.1.78 it uses the new JSON object format; otherwise the
// legacy "user_{hex}_account__session_{uuid}" string format.
// When sessionSeed is provided, the clientID and sessionUUID are derived
// deterministically so the same seed always produces the same identity.
func GenerateUserID(sessionSeed, uaVersion string) string {
	var clientID string
	if sessionSeed != "" {
		clientID = deterministicClientID(sessionSeed, "default-client")
	} else {
		clientID = GenerateClientID()
	}
	sessionUUID := generateSessionUUID(sessionSeed)

	if isNewMetadataFormatVersion(uaVersion) {
		obj := userIDJSON{DeviceID: clientID, SessionID: sessionUUID}
		b, _ := json.Marshal(obj)
		return string(b)
	}
	return fmt.Sprintf("user_%s_account__session_%s", clientID, sessionUUID)
}
```

- [ ] **Step 4: Update RewriteUserIDWithMasking in metadata.go**

Replace the existing `RewriteUserIDWithMasking` function:

```go
// RewriteUserIDWithMasking rewrites a client's user_id to prevent Anthropic from
// correlating different proxy users, replacing the session portion with maskedSessionUUID.
// Output format follows the input format, unless uaVersion >= 2.1.78 forces JSON.
// Falls back to a deterministic generated ID if the original cannot be parsed.
func RewriteUserIDWithMasking(originalUserID, accountSeed, maskedSessionUUID, uaVersion string) string {
	parsed := ParseUserID(originalUserID)

	useJSON := isNewMetadataFormatVersion(uaVersion)

	if parsed == nil {
		// Unknown format: generate deterministic client ID and use masked session
		clientID := deterministicClientID(accountSeed, "default-client")
		if accountSeed == "" {
			clientID = GenerateClientID()
		}
		if useJSON {
			obj := userIDJSON{DeviceID: clientID, SessionID: maskedSessionUUID}
			b, _ := json.Marshal(obj)
			return string(b)
		}
		return fmt.Sprintf("user_%s_account__session_%s", clientID, maskedSessionUUID)
	}

	newClient := deterministicClientID(accountSeed, parsed.DeviceID)

	if parsed.IsNewFormat || useJSON {
		obj := userIDJSON{DeviceID: newClient, SessionID: maskedSessionUUID}
		if parsed.AccountUUID != "" {
			obj.AccountUUID = generateSessionUUID(accountSeed + parsed.AccountUUID)
		}
		b, _ := json.Marshal(obj)
		return string(b)
	}

	// Legacy string formats
	if parsed.AccountUUID != "" {
		newAccount := generateSessionUUID(accountSeed + parsed.AccountUUID)
		return fmt.Sprintf("user_%s_account_%s_session_%s", newClient, newAccount, maskedSessionUUID)
	}
	return fmt.Sprintf("user_%s_account__session_%s", newClient, maskedSessionUUID)
}
```

- [ ] **Step 5: Update RewriteUserID (non-masking variant) in metadata.go**

Replace the existing `RewriteUserID` function (add `uaVersion` for consistency; callers in tests need updating too):

```go
// RewriteUserID deterministically rewrites a client's user_id to prevent
// Anthropic from correlating different proxy users.
// Falls back to GenerateUserID when the original cannot be parsed.
func RewriteUserID(originalUserID, accountSeed, uaVersion string) string {
	parsed := ParseUserID(originalUserID)
	if parsed == nil {
		return GenerateUserID(accountSeed, uaVersion)
	}

	newClient := deterministicClientID(accountSeed, parsed.DeviceID)
	newSession := generateSessionUUID(accountSeed + parsed.SessionID)

	if parsed.IsNewFormat || isNewMetadataFormatVersion(uaVersion) {
		obj := userIDJSON{DeviceID: newClient, SessionID: newSession}
		if parsed.AccountUUID != "" {
			obj.AccountUUID = generateSessionUUID(accountSeed + parsed.AccountUUID)
		}
		b, _ := json.Marshal(obj)
		return string(b)
	}

	if parsed.AccountUUID != "" {
		newAccount := generateSessionUUID(accountSeed + parsed.AccountUUID)
		return fmt.Sprintf("user_%s_account_%s_session_%s", newClient, newAccount, newSession)
	}
	return fmt.Sprintf("user_%s_account__session_%s", newClient, newSession)
}
```

- [ ] **Step 6: Update existing test calls that use old signatures**

In `metadata_test.go`, the existing tests call:
- `GenerateUserID("")` → change to `GenerateUserID("", "")`
- `GenerateUserID("my-session-seed")` → `GenerateUserID("my-session-seed", "")`
- `GenerateUserID("seed-alpha")` → `GenerateUserID("seed-alpha", "")`
- `GenerateUserID("seed-beta")` → `GenerateUserID("seed-beta", "")`
- `RewriteUserID(original, "my-account-seed")` → `RewriteUserID(original, "my-account-seed", "")`
- `RewriteUserID(original, "seed-x")` → `RewriteUserID(original, "seed-x", "")`
- `RewriteUserID(original, "seed-a")` → `RewriteUserID(original, "seed-a", "")`
- `RewriteUserID(original, "seed-b")` → `RewriteUserID(original, "seed-b", "")`
- `RewriteUserID("some-random-user-id", "seed")` → `RewriteUserID("some-random-user-id", "seed", "")`
- `RewriteUserIDWithMasking(original, "my-seed", masked)` → `RewriteUserIDWithMasking(original, "my-seed", masked, "")`
- `RewriteUserIDWithMasking("random-id", "seed", masked)` → `RewriteUserIDWithMasking("random-id", "seed", masked, "")`

- [ ] **Step 7: Run all metadata tests**

```bash
go test ./internal/disguise/... -run "TestGenerateUserID|TestRewriteUserID|TestParseUserID|TestCompareVersions" -v -race 2>&1 | tail -30
```

Expected: all PASS (engine.go will fail to compile — fix in Task 3)

---

## Task 3: Update engine.go to pass uaVersion

**Files:**
- Modify: `internal/disguise/engine.go`

Three call sites to update: CC path (2 calls), non-CC path (`injectMetadataUserIDInPlace`).

- [ ] **Step 1: Add UA version extraction helper to engine.go**

At the top of `engine.go`, add a package-level regex and helper (near the other package-level vars):

```go
var uaVersionRegex = regexp.MustCompile(`^claude-cli/(\d+\.\d+\.\d+)`)

// extractUAVersion extracts the version string from a Claude CLI User-Agent.
// Returns "" if the UA does not match the expected pattern.
func extractUAVersion(ua string) string {
	m := uaVersionRegex.FindStringSubmatch(ua)
	if m == nil {
		return ""
	}
	return m[1]
}
```

- [ ] **Step 2: Update CC path in Apply()**

In the CC client branch of `Apply()` (around line 88-105 in the original), extract version and pass it:

Find this code block:
```go
maskedSession := e.sessions.Get(accountName)
originalUserID, _ := metadata["user_id"].(string)
if originalUserID != "" {
    metadata["user_id"] = RewriteUserIDWithMasking(originalUserID, sessionSeed, maskedSession)
} else {
    metadata["user_id"] = GenerateUserID(sessionSeed)
}
```

Replace with:
```go
maskedSession := e.sessions.Get(accountName)
uaVersion := extractUAVersion(origReq.Header.Get("User-Agent"))
originalUserIDRaw := metadata["user_id"]
// user_id may be a string (old format) or map[string]interface{} (new JSON format)
var originalUserIDStr string
switch v := originalUserIDRaw.(type) {
case string:
    originalUserIDStr = v
case map[string]interface{}:
    // JSON object format: re-marshal to string for ParseUserID
    if b, err := json.Marshal(v); err == nil {
        originalUserIDStr = string(b)
    }
}
if originalUserIDStr != "" {
    metadata["user_id"] = RewriteUserIDWithMasking(originalUserIDStr, sessionSeed, maskedSession, uaVersion)
} else {
    metadata["user_id"] = GenerateUserID(sessionSeed, uaVersion)
}
```

- [ ] **Step 3: Update the user_id truncation log line**

The `truncateUserID` call that follows references `metadata["user_id"].(string)`. Update it to handle non-string types:

Find:
```go
observe.Logger(ctx).Debug("disguise: user_id rewritten (CC pass-through)",
    "account", accountName,
    "before", truncateUserID(originalUserID),
    "after", truncateUserID(metadata["user_id"].(string)),
)
```

Replace with:
```go
newUserIDStr := fmt.Sprintf("%v", metadata["user_id"])
observe.Logger(ctx).Debug("disguise: user_id rewritten (CC pass-through)",
    "account", accountName,
    "before", truncateUserID(originalUserIDStr),
    "after", truncateUserID(newUserIDStr),
)
```

- [ ] **Step 4: Update injectMetadataUserIDInPlace signature and body**

Find the function definition:
```go
func injectMetadataUserIDInPlace(parsed map[string]interface{}, sessionSeed string, maskedSessionUUID string) {
	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
	}
	userID := GenerateUserID(sessionSeed)
	// Replace the session UUID portion with the masked session UUID
	if maskedSessionUUID != "" {
		parts := strings.SplitN(userID, "_account__session_", 2)
		if len(parts) == 2 {
			userID = parts[0] + "_account__session_" + maskedSessionUUID
		}
	}
	metadata["user_id"] = userID
	parsed["metadata"] = metadata
}
```

Replace entirely with:
```go
func injectMetadataUserIDInPlace(parsed map[string]interface{}, sessionSeed string, maskedSessionUUID string, uaVersion string) {
	metadata, ok := parsed["metadata"].(map[string]interface{})
	if !ok {
		metadata = make(map[string]interface{})
	}

	var clientID string
	if sessionSeed != "" {
		clientID = deterministicClientID(sessionSeed, "default-client")
	} else {
		clientID = GenerateClientID()
	}

	sessionID := maskedSessionUUID
	if sessionID == "" {
		sessionID = generateSessionUUID(sessionSeed)
	}

	var userID string
	if isNewMetadataFormatVersion(uaVersion) {
		obj := userIDJSON{DeviceID: clientID, SessionID: sessionID}
		b, _ := json.Marshal(obj)
		userID = string(b)
	} else {
		userID = fmt.Sprintf("user_%s_account__session_%s", clientID, sessionID)
	}

	metadata["user_id"] = userID
	parsed["metadata"] = metadata
}
```

- [ ] **Step 5: Update the call site of injectMetadataUserIDInPlace in Apply()**

Find:
```go
injectMetadataUserIDInPlace(parsed, sessionSeed, maskedSession)
```

Determine the correct `uaVersion` to use for the non-CC path. The disguise fingerprint's UserAgent represents what version we're impersonating. Add before the call:

```go
// For non-CC path, use the fingerprint UA version to determine user_id format.
// Default fingerprint is claude-cli/2.1.22, so old format is used by default.
fpUAVersion := ""
if fp != nil {
    fpUAVersion = extractUAVersion(fp.UserAgent)
} else {
    fpUAVersion = extractUAVersion(DefaultHeaders["User-Agent"])
}
injectMetadataUserIDInPlace(parsed, sessionSeed, maskedSession, fpUAVersion)
```

Note: `fp` and `maskedSession` are in scope here — `fp` is declared at the Layer 2 step (line ~129), `maskedSession` at the Layer 5 step (line ~205). Verify the variable names are in scope at line 210 in the original.

- [ ] **Step 6: Build to verify no compile errors**

```bash
go build ./internal/disguise/... ./internal/proxy/... 2>&1
```

Expected: no errors

- [ ] **Step 7: Run full disguise test suite**

```bash
go test ./internal/disguise/... -v -race 2>&1 | tail -40
```

Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add internal/disguise/metadata.go internal/disguise/metadata_test.go internal/disguise/engine.go
git commit -m "feat(disguise): support CLI>=2.1.78 JSON format for metadata.user_id"
```

---

## Task 4: Update detector signal 3 for JSON format user_id

**Files:**
- Modify: `internal/disguise/detector.go`
- Test: `internal/disguise/detector_test.go`

The `detectorRequest` struct decodes `metadata.user_id` as `string`, which silently becomes `""` when the actual JSON value is an object. Signal 3 (`hasUserID`) therefore always scores 0 for CLI ≥ 2.1.78 clients.

- [ ] **Step 1: Write the failing test**

Append to `internal/disguise/detector_test.go`:

```go
func TestIsClaudeCodeClient_JSONFormatUserID(t *testing.T) {
	t.Parallel()
	// CLI >= 2.1.78 sends user_id as JSON object, not string.
	// Detector must score signal 3 for this format.
	deviceID := strings.Repeat("ab", 32)
	userIDObj := `{"device_id":"` + deviceID + `","session_id":"sess-uuid-123"}`
	body := []byte(`{
		"model": "claude-sonnet-4-5-20250929",
		"max_tokens": 1024,
		"metadata": {"user_id": ` + userIDObj + `},
		"system": "You are Claude Code, Anthropic's official CLI for Claude.",
		"messages": [{"role":"user","content":"hi"}]
	}`)
	headers := http.Header{}
	headers.Set("User-Agent", "claude-cli/2.1.78 (external, cli)")
	headers.Set("X-App", "cli")
	headers.Set("Anthropic-Version", "2023-06-01")

	got := IsClaudeCodeClient(headers, body, "/v1/messages")
	if !got {
		t.Error("expected IsClaudeCodeClient=true for CLI 2.1.78 JSON user_id format")
	}
}
```

- [ ] **Step 2: Run test to confirm it fails**

```bash
go test ./internal/disguise/... -run "TestIsClaudeCodeClient_JSONFormatUserID" -v 2>&1
```

Expected: FAIL (test reports false, expected true — because signal 3 scores 0)

- [ ] **Step 3: Change detectorRequest.Metadata.UserID to json.RawMessage**

In `detector.go`, update the `detectorRequest` struct:

```go
type detectorRequest struct {
	Model     string      `json:"model"`
	MaxTokens int         `json:"max_tokens"`
	Stream    bool        `json:"stream"`
	Metadata  struct {
		UserIDRaw json.RawMessage `json:"user_id"`
	} `json:"metadata"`
	System interface{} `json:"system"`
}
```

- [ ] **Step 4: Add validUserIDRaw helper and update signal 3**

Add after the struct definition in `detector.go`:

```go
// validUserIDRaw checks whether a raw JSON value is a valid Claude Code user_id.
// Handles both old string format and new JSON object format (CLI >= 2.1.78).
func validUserIDRaw(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	// Old format: JSON-encoded string
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return ParseUserID(s) != nil
	}
	// New format: JSON object with device_id + session_id
	var obj struct {
		DeviceID  string `json:"device_id"`
		SessionID string `json:"session_id"`
	}
	return json.Unmarshal(raw, &obj) == nil && obj.DeviceID != "" && obj.SessionID != ""
}
```

Then update signal 3 in `IsClaudeCodeClient`:

Find:
```go
hasUserID := metadataRegex.MatchString(req.Metadata.UserID)
```

Replace with:
```go
hasUserID := validUserIDRaw(req.Metadata.UserIDRaw)
```

The `metadataRegex` variable is still used elsewhere (or remove it if unused — check with grep first).

- [ ] **Step 5: Check if metadataRegex is still needed**

```bash
grep -n "metadataRegex" internal/disguise/detector.go internal/disguise/detector_test.go
```

If only the signal 3 line used it, remove the `metadataRegex` declaration from the `var` block.

- [ ] **Step 6: Run the failing test — expect PASS**

```bash
go test ./internal/disguise/... -run "TestIsClaudeCodeClient_JSONFormatUserID" -v -race 2>&1
```

Expected: PASS

- [ ] **Step 7: Run full detector test suite**

```bash
go test ./internal/disguise/... -v -race 2>&1 | tail -40
```

Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add internal/disguise/detector.go internal/disguise/detector_test.go
git commit -m "fix(disguise): detect CLI>=2.1.78 JSON format user_id in signal 3"
```

---

## Task 5: Strip empty text blocks after thinking conversion

**Files:**
- Modify: `internal/proxy/bodyfilter.go`
- Test: `internal/proxy/bodyfilter_test.go`

When `thinking` content is `""`, conversion produces `{"type":"text","text":""}`. Anthropic rejects these with 400.

- [ ] **Step 1: Write the failing test**

Append to `internal/proxy/bodyfilter_test.go`:

```go
func TestFilterThinkingBlocks_EmptyThinkingProducesNoEmptyText(t *testing.T) {
	t.Parallel()
	body := []byte(`{
		"messages": [{
			"role": "assistant",
			"content": [
				{"type": "thinking", "thinking": ""},
				{"type": "text", "text": "hello"}
			]
		}]
	}`)
	result := FilterThinkingBlocks(body)

	var parsed struct {
		Messages []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	for _, msg := range parsed.Messages {
		for _, block := range msg.Content {
			if block.Type == "text" && block.Text == "" {
				t.Errorf("found empty text block in output: %s", result)
			}
		}
	}
}

func TestFilterThinkingBlocks_AllEmptyThinkingKeepsPlaceholder(t *testing.T) {
	t.Parallel()
	// When all blocks are empty thinking, the result should have the placeholder,
	// not an empty content array.
	body := []byte(`{
		"messages": [{
			"role": "assistant",
			"content": [
				{"type": "thinking", "thinking": ""},
				{"type": "thinking", "thinking": ""}
			]
		}]
	}`)
	result := FilterThinkingBlocks(body)

	var parsed struct {
		Messages []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if len(parsed.Messages[0].Content) == 0 {
		t.Error("expected placeholder block, got empty content array")
	}
	// The placeholder block must have non-empty text
	for _, block := range parsed.Messages[0].Content {
		if block.Text == "" {
			t.Errorf("expected placeholder with non-empty text, got empty block")
		}
	}
}

func TestStripEmptyTextBlocks(t *testing.T) {
	t.Parallel()
	content := []any{
		map[string]any{"type": "text", "text": ""},
		map[string]any{"type": "text", "text": "hello"},
		map[string]any{"type": "text", "text": ""},
		map[string]any{"type": "thinking", "thinking": "thought"},
	}
	got := stripEmptyTextBlocks(content)
	if len(got) != 2 {
		t.Errorf("expected 2 blocks after stripping, got %d: %v", len(got), got)
	}
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
go test ./internal/proxy/... -run "TestFilterThinkingBlocks_EmptyThinking|TestStripEmptyTextBlocks" -v 2>&1 | head -20
```

Expected: `TestFilterThinkingBlocks_EmptyThinkingProducesNoEmptyText` FAIL, `stripEmptyTextBlocks` undefined.

- [ ] **Step 3: Add stripEmptyTextBlocks to bodyfilter.go**

Add the function after `filterThinkingFromContent`:

```go
// stripEmptyTextBlocks removes any block where type=="text" and text=="".
// These can arise when thinking blocks with no content are converted to text.
func stripEmptyTextBlocks(content []any) []any {
	result := make([]any, 0, len(content))
	for _, block := range content {
		blockMap, ok := block.(map[string]any)
		if !ok {
			result = append(result, block)
			continue
		}
		if blockType, _ := blockMap["type"].(string); blockType == "text" {
			if text, _ := blockMap["text"].(string); text == "" {
				continue // skip empty text block
			}
		}
		result = append(result, block)
	}
	return result
}
```

- [ ] **Step 4: Call stripEmptyTextBlocks in filterBlocks**

In `filterBlocks`, after `contentFilter` is applied, add the strip call:

Find:
```go
msgMap["content"] = contentFilter(content)
```

Replace with:
```go
filtered := contentFilter(content)
filtered = stripEmptyTextBlocks(filtered)
if len(filtered) == 0 {
    filtered = []any{map[string]any{"type": "text", "text": "(content removed)"}}
}
msgMap["content"] = filtered
```

Also remove the empty-array guard at the end of `filterThinkingFromContent` since `filterBlocks` now handles it centrally:

Find in `filterThinkingFromContent`:
```go
if len(result) == 0 {
    result = append(result, map[string]any{
        "type": "text",
        "text": "(content removed)",
    })
}
return result
```

Replace with:
```go
return result
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/proxy/... -v -race 2>&1 | tail -30
```

Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/bodyfilter.go internal/proxy/bodyfilter_test.go
git commit -m "fix(proxy): strip empty text blocks produced by thinking conversion"
```

---

## Task 6: Sync system prompt prefix list

**Files:**
- Modify: `internal/disguise/detector.go`

Small targeted change — update entry #4 text to match sub2api's full form.

- [ ] **Step 1: Update claudeCodePromptPrefixes in detector.go**

Find:
```go
var claudeCodePromptPrefixes = []string{
	"You are Claude Code, Anthropic's official CLI for Claude",
	"You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.",
	"You are a Claude agent, built on Anthropic's Claude Agent SDK",
	"You are a file search specialist for Claude Code",
	"You are a helpful AI assistant tasked with summarizing conversations",
	"You are an agent for Claude Code",
	"You are an interactive CLI tool that helps users",
	"You are Claude, made by Anthropic",
}
```

Replace with:
```go
var claudeCodePromptPrefixes = []string{
	"You are Claude Code, Anthropic's official CLI for Claude",
	"You are Claude Code, Anthropic's official CLI for Claude, running within the Claude Agent SDK.",
	"You are a Claude agent, built on Anthropic's Claude Agent SDK",
	"You are a file search specialist for Claude Code, Anthropic's official CLI for Claude.",
	"You are a helpful AI assistant tasked with summarizing conversations",
	"You are an agent for Claude Code",
	"You are an interactive CLI tool that helps users",
	"You are Claude, made by Anthropic",
}
```

Only entry #4 changes (extended to full form).

- [ ] **Step 2: Run all tests**

```bash
go test ./internal/disguise/... -v -race 2>&1 | tail -20
```

Expected: all PASS

- [ ] **Step 3: Commit**

```bash
git add internal/disguise/detector.go
git commit -m "fix(disguise): sync file-search prefix to full form matching sub2api"
```

---

## Task 7: Full test suite + final verification

- [ ] **Step 1: Run the complete test suite**

```bash
go test ./... -race 2>&1 | tail -30
```

Expected: all PASS, no data races

- [ ] **Step 2: Build the binary**

```bash
make build 2>&1
```

Expected: `bin/ccproxy` built with no errors

- [ ] **Step 3: Commit if there are any leftover staged changes**

```bash
git status
```

If clean, done. If there are uncommitted changes, commit them:

```bash
git add -u
git commit -m "chore(disguise): cleanup after sub2api alignment"
```
