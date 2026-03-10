package disguise

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
)

// GenerateClientID generates a random 64-character hex string (32 bytes).
func GenerateClientID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// GenerateUserID creates a metadata.user_id in Claude Code format.
// Format: user_{64hex}_account__session_{uuid}
func GenerateUserID(sessionSeed string) string {
	clientID := GenerateClientID()
	var sessionUUID string
	if sessionSeed != "" {
		sessionUUID = uuid.NewSHA1(uuid.NameSpaceDNS, []byte(sessionSeed)).String()
	} else {
		sessionUUID = uuid.New().String()
	}
	return fmt.Sprintf("user_%s_account__session_%s", clientID, sessionUUID)
}
