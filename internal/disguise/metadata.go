package disguise

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
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

// GenerateUserID creates a metadata.user_id in Claude Code format.
// Format: user_{64hex}_account__session_{uuid}
func GenerateUserID(sessionSeed string) string {
	clientID := GenerateClientID()
	sessionUUID := generateSessionUUID(sessionSeed)
	return fmt.Sprintf("user_%s_account__session_%s", clientID, sessionUUID)
}
