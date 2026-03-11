package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// codeVerifierCharset is the RFC 7636 compliant character set for PKCE verifiers.
const codeVerifierCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

// base64URLEncode encodes bytes to base64url without padding (matches sub2api).
func base64URLEncode(data []byte) string {
	encoded := base64.URLEncoding.EncodeToString(data)
	return strings.TrimRight(encoded, "=")
}

// GenerateVerifier creates a PKCE code verifier.
// Generates 32 characters from codeVerifierCharset, then base64url encodes them.
func GenerateVerifier() string {
	const targetLen = 32
	charsetLen := len(codeVerifierCharset)
	limit := 256 - (256%charsetLen)

	result := make([]byte, 0, targetLen)
	randBuf := make([]byte, targetLen*2)

	for len(result) < targetLen {
		if _, err := rand.Read(randBuf); err != nil {
			panic("crypto/rand: " + err.Error())
		}
		for _, b := range randBuf {
			if int(b) < limit {
				result = append(result, codeVerifierCharset[int(b)%charsetLen])
				if len(result) >= targetLen {
					break
				}
			}
		}
	}

	return base64URLEncode(result)
}

// GenerateChallenge creates a PKCE code challenge from a verifier (SHA-256, base64url).
func GenerateChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64URLEncode(h[:])
}

// GenerateState creates a random state parameter for OAuth (32 bytes, base64url).
func GenerateState() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	return base64URLEncode(b)
}
