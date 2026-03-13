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
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
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
	path  string
	key   []byte
	mu    sync.RWMutex
	cache map[string]*OAuthToken // in-memory cache, populated on first loadFile
	loaded bool                  // whether cache has been populated from disk
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
	return &TokenStore{
		path:  path,
		key:   key,
		cache: make(map[string]*OAuthToken),
	}, nil
}

func (s *TokenStore) Save(providerName string, token OAuthToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureCacheLoaded()

	// Update cache
	t := token // copy
	s.cache[providerName] = &t

	return s.persistToDisk()
}

func (s *TokenStore) Load(providerName string) (*OAuthToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.loaded {
		// Need write lock to populate cache
		s.mu.RUnlock()
		s.mu.Lock()
		s.ensureCacheLoaded()
		s.mu.Unlock()
		s.mu.RLock()
	}

	token, ok := s.cache[providerName]
	if !ok {
		return nil, nil
	}
	// Return a copy to prevent mutation
	t := *token
	return &t, nil
}

func (s *TokenStore) Delete(providerName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureCacheLoaded()
	delete(s.cache, providerName)
	return s.persistToDisk()
}

func (s *TokenStore) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.loaded {
		s.mu.RUnlock()
		s.mu.Lock()
		s.ensureCacheLoaded()
		s.mu.Unlock()
		s.mu.RLock()
	}

	names := make([]string, 0, len(s.cache))
	for name := range s.cache {
		names = append(names, name)
	}
	return names
}

// ensureCacheLoaded populates the in-memory cache from disk on first access.
// Must be called under write lock.
func (s *TokenStore) ensureCacheLoaded() {
	if s.loaded {
		return
	}
	data := s.loadFile()
	for name, encrypted := range data.Tokens {
		plaintext, err := decrypt(encrypted, s.key)
		if err != nil {
			slog.Warn("oauth/store: failed to decrypt token on cache load", "provider", name, "error", err.Error())
			continue
		}
		var token OAuthToken
		if err := json.Unmarshal(plaintext, &token); err != nil {
			slog.Warn("oauth/store: failed to parse token on cache load", "provider", name, "error", err.Error())
			continue
		}
		s.cache[name] = &token
	}
	s.loaded = true
}

// persistToDisk writes the current cache state to disk atomically.
// Must be called under write lock.
func (s *TokenStore) persistToDisk() error {
	data := &tokenFileData{Tokens: make(map[string][]byte, len(s.cache))}
	for name, token := range s.cache {
		plaintext, err := json.Marshal(token)
		if err != nil {
			return fmt.Errorf("marshal token %s: %w", name, err)
		}
		encrypted, err := encrypt(plaintext, s.key)
		if err != nil {
			return fmt.Errorf("encrypt token %s: %w", name, err)
		}
		data.Tokens[name] = encrypted
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path, b, 0600)
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

// atomicWriteFile writes data to a temporary file and renames it to path,
// ensuring the target file is never left in a half-written state.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	return os.Rename(tmpPath, path)
}

func deriveKey() ([]byte, error) {
	hostname, _ := os.Hostname()

	username := "default"
	if u, err := user.Current(); err == nil && u.Username != "" {
		username = u.Username
	}

	mid := machineID()

	// Use hostname + username + machineID as password material
	password := fmt.Sprintf("ccproxy-%s-%s-%s", hostname, username, mid)
	salt := []byte(fmt.Sprintf("ccproxy-%s-%s", hostname, username))

	// Argon2id key derivation
	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	return key, nil
}

// machineID returns a platform-specific machine identifier.
// Returns empty string on unsupported platforms or errors.
func machineID() string {
	switch runtime.GOOS {
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if err != nil {
			return ""
		}
		re := regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
		matches := re.FindSubmatch(out)
		if len(matches) < 2 {
			return ""
		}
		return string(matches[1])
	case "linux":
		data, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(data))
	default:
		return ""
	}
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
