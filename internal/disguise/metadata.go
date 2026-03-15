package disguise

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
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
// Anthropic from correlating different proxy users. The clientID portion is
// replaced with sha256(accountSeed + originalClientID)[:32] (64 hex chars),
// and the session UUID is re-derived via generateSessionUUID(accountSeed + originalSession).
//
// If the original user_id does not match any known format, falls back to GenerateUserID.
func RewriteUserID(originalUserID, accountSeed string) string {
	// Try format A: user_{hex}_account__session_{uuid}
	if m := userIDFormatA.FindStringSubmatch(originalUserID); m != nil {
		clientHex := m[1]
		sessionUUID := m[2]
		newClient := deterministicClientID(accountSeed, clientHex)
		newSession := generateSessionUUID(accountSeed + sessionUUID)
		return fmt.Sprintf("user_%s_account__session_%s", newClient, newSession)
	}

	// Try format B: user_{hex}_account_{uuid}_session_{uuid}
	if m := userIDFormatB.FindStringSubmatch(originalUserID); m != nil {
		clientHex := m[1]
		accountUUID := m[2]
		sessionUUID := m[3]
		newClient := deterministicClientID(accountSeed, clientHex)
		newAccount := generateSessionUUID(accountSeed + accountUUID)
		newSession := generateSessionUUID(accountSeed + sessionUUID)
		return fmt.Sprintf("user_%s_account_%s_session_%s", newClient, newAccount, newSession)
	}

	// Fallback: unknown format, generate fresh
	return GenerateUserID(accountSeed)
}

// deterministicClientID derives a 64-char hex string from seed + originalClientID.
func deterministicClientID(accountSeed, originalClientID string) string {
	hash := sha256.Sum256([]byte(accountSeed + originalClientID))
	return hex.EncodeToString(hash[:])
}

// RewriteUserIDWithMasking works like RewriteUserID but replaces the session UUID
// portion with the provided maskedSessionUUID to ensure all requests through the
// same account share a consistent session identity.
func RewriteUserIDWithMasking(originalUserID, accountSeed, maskedSessionUUID string) string {
	// Try format A: user_{hex}_account__session_{uuid}
	if m := userIDFormatA.FindStringSubmatch(originalUserID); m != nil {
		clientHex := m[1]
		newClient := deterministicClientID(accountSeed, clientHex)
		return fmt.Sprintf("user_%s_account__session_%s", newClient, maskedSessionUUID)
	}

	// Try format B: user_{hex}_account_{uuid}_session_{uuid}
	if m := userIDFormatB.FindStringSubmatch(originalUserID); m != nil {
		clientHex := m[1]
		accountUUID := m[2]
		newClient := deterministicClientID(accountSeed, clientHex)
		newAccount := generateSessionUUID(accountSeed + accountUUID)
		return fmt.Sprintf("user_%s_account_%s_session_%s", newClient, newAccount, maskedSessionUUID)
	}

	// Fallback: unknown format, derive deterministic clientID from seed
	var clientID string
	if accountSeed != "" {
		clientID = deterministicClientID(accountSeed, "default-client")
	} else {
		clientID = GenerateClientID()
	}
	return fmt.Sprintf("user_%s_account__session_%s", clientID, maskedSessionUUID)
}

// GenerateUserID creates a metadata.user_id in Claude Code format.
// Format: user_{64hex}_account__session_{uuid}
// When sessionSeed is provided, both clientID and sessionUUID are derived
// deterministically so the same seed produces a stable identity.
func GenerateUserID(sessionSeed string) string {
	var clientID string
	if sessionSeed != "" {
		clientID = deterministicClientID(sessionSeed, "default-client")
	} else {
		clientID = GenerateClientID()
	}
	sessionUUID := generateSessionUUID(sessionSeed)
	return fmt.Sprintf("user_%s_account__session_%s", clientID, sessionUUID)
}
