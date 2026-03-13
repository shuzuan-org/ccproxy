package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

type OAuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Scope        string    `json:"scope"`
}

type tokenFileData struct {
	Tokens map[string][]byte `json:"tokens"` // providerName → encrypted token JSON
}

type TokenStore struct {
	path string
	key  []byte
	mu   sync.RWMutex
}

func NewTokenStore(dataDir string) (*TokenStore, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "oauth_tokens.json")
	key, err := deriveKey()
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return &TokenStore{path: path, key: key}, nil
}

func (s *TokenStore) Save(providerName string, token OAuthToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := s.loadFile()
	plaintext, err := json.Marshal(token)
	if err != nil {
		return err
	}
	encrypted, err := encrypt(plaintext, s.key)
	if err != nil {
		return err
	}
	data.Tokens[providerName] = encrypted
	return s.saveFile(data)
}

func (s *TokenStore) Load(providerName string) (*OAuthToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := s.loadFile()
	encrypted, ok := data.Tokens[providerName]
	if !ok {
		return nil, nil
	}
	plaintext, err := decrypt(encrypted, s.key)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	var token OAuthToken
	if err := json.Unmarshal(plaintext, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *TokenStore) Delete(providerName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data := s.loadFile()
	delete(data.Tokens, providerName)
	return s.saveFile(data)
}

func (s *TokenStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data := s.loadFile()
	names := make([]string, 0, len(data.Tokens))
	for name := range data.Tokens {
		names = append(names, name)
	}
	return names
}

func (s *TokenStore) loadFile() *tokenFileData {
	data := &tokenFileData{Tokens: make(map[string][]byte)}
	f, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("oauth/store: failed to read token file", "path", s.path, "error", err.Error())
		}
		return data
	}
	if err := json.Unmarshal(f, data); err != nil {
		slog.Warn("oauth/store: corrupted token file, starting empty", "path", s.path, "error", err.Error())
		data.Tokens = make(map[string][]byte)
	}
	if data.Tokens == nil {
		data.Tokens = make(map[string][]byte)
	}
	return data
}

func (s *TokenStore) saveFile(data *tokenFileData) error {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0600)
}

func deriveKey() ([]byte, error) {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = "default"
	}
	// Use hostname + username as salt material
	salt := []byte(fmt.Sprintf("ccproxy-%s-%s", hostname, username))
	// Argon2id key derivation
	key := argon2.IDKey([]byte("ccproxy-token-store"), salt, 1, 64*1024, 4, 32)
	return key, nil
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
