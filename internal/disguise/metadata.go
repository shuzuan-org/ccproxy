package disguise

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

// GenerateClientID generates a random 64-character hex string (32 bytes).
func GenerateClientID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// generateSessionUUID derives a deterministic UUID-like string from a seed
// using SHA256, matching sub2api's generateSessionUUID implementation.
func generateSessionUUID(seed string) string {
	if seed == "" {
		// No seed: generate a random UUID v4
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			panic("crypto/rand: " + err.Error())
		}
		b[6] = (b[6] & 0x0f) | 0x40 // version 4
		b[8] = (b[8] & 0x3f) | 0x80 // variant 1
		return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	}
	hash := sha256.Sum256([]byte(seed))
	b := hash[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// userIDFormats matches the two known Claude Code user_id formats:
// Format A: user_{64hex}_account__session_{uuid}  (double underscore, no account UUID)
// Format B: user_{64hex}_account_{uuid}_session_{uuid}
var userIDFormatA = regexp.MustCompile(`^user_([a-fA-F0-9]{64})_account__session_([\w-]+)$`)
var userIDFormatB = regexp.MustCompile(`^user_([a-fA-F0-9]{64})_account_([\w-]+)_session_([\w-]+)$`)

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

// deterministicClientID derives a 64-char hex string from seed + originalClientID.
func deterministicClientID(accountSeed, originalClientID string) string {
	hash := sha256.Sum256([]byte(accountSeed + originalClientID))
	return hex.EncodeToString(hash[:])
}

// RewriteUserIDWithFixedClient rewrites user_id using the account's fixed per-account
// ClientID (same for all users of this account), aligning with sub2api's fp.ClientID strategy.
// All users sharing the same proxy account will have identical device_id in their user_id,
// making all traffic appear to originate from a single device.
// Falls back to a generated ID when fixedClientID is empty.
func RewriteUserIDWithFixedClient(originalUserID, fixedClientID, maskedSessionUUID, uaVersion string) string {
	parsed := ParseUserID(originalUserID)
	useJSON := isNewMetadataFormatVersion(uaVersion)

	clientID := fixedClientID
	if clientID == "" {
		clientID = GenerateClientID()
	}

	if parsed == nil {
		if useJSON {
			obj := userIDJSON{DeviceID: clientID, SessionID: maskedSessionUUID}
			b, _ := json.Marshal(obj)
			return string(b)
		}
		return fmt.Sprintf("user_%s_account__session_%s", clientID, maskedSessionUUID)
	}

	if parsed.IsNewFormat || useJSON {
		obj := userIDJSON{DeviceID: clientID, SessionID: maskedSessionUUID}
		if parsed.AccountUUID != "" {
			obj.AccountUUID = generateSessionUUID(clientID + parsed.AccountUUID)
		}
		b, _ := json.Marshal(obj)
		return string(b)
	}

	// Legacy string formats
	if parsed.AccountUUID != "" {
		newAccount := generateSessionUUID(clientID + parsed.AccountUUID)
		return fmt.Sprintf("user_%s_account_%s_session_%s", clientID, newAccount, maskedSessionUUID)
	}
	return fmt.Sprintf("user_%s_account__session_%s", clientID, maskedSessionUUID)
}

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
