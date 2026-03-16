package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/binn/ccproxy/internal/fileutil"
)

// Account represents a dynamically managed backend account.
type Account struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Proxy   string `json:"proxy,omitempty"`
}

// AccountRegistry manages a persistent list of accounts stored in data/accounts.json.
type AccountRegistry struct {
	mu       sync.RWMutex
	path     string
	accounts []Account
	onChange func([]Account)
	changeCh chan []Account // serialized change notifications
}

// NewAccountRegistry creates or loads an AccountRegistry from the given data directory.
func NewAccountRegistry(dataDir string) *AccountRegistry {
	path := filepath.Join(dataDir, "accounts.json")
	r := &AccountRegistry{path: path}
	if err := r.load(); err != nil {
		slog.Warn("registry: failed to load accounts file, starting empty", "path", path, "error", err.Error())
	} else {
		slog.Info("registry: loaded accounts", "path", path, "count", len(r.accounts))
	}
	return r
}

// Add adds a new account with the given name. Returns an error if the name
// is empty, contains invalid characters, or is already taken.
func (r *AccountRegistry) Add(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("account name cannot be empty")
	}

	r.mu.Lock()

	for _, acct := range r.accounts {
		if acct.Name == name {
			r.mu.Unlock()
			return fmt.Errorf("account %q already exists", name)
		}
	}

	r.accounts = append(r.accounts, Account{Name: name, Enabled: true})
	if err := r.save(); err != nil {
		// Roll back
		r.accounts = r.accounts[:len(r.accounts)-1]
		r.mu.Unlock()
		return fmt.Errorf("persist account: %w", err)
	}

	// Send snapshot to serialized change channel
	r.notifyChange()
	r.mu.Unlock()

	return nil
}

// Remove removes the account with the given name.
func (r *AccountRegistry) Remove(name string) error {
	r.mu.Lock()

	idx := -1
	for i, acct := range r.accounts {
		if acct.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		r.mu.Unlock()
		return fmt.Errorf("account %q not found", name)
	}

	// Save full snapshot before mutating the slice for safe rollback
	original := make([]Account, len(r.accounts))
	copy(original, r.accounts)

	r.accounts = append(r.accounts[:idx], r.accounts[idx+1:]...)
	if err := r.save(); err != nil {
		r.accounts = original
		r.mu.Unlock()
		return fmt.Errorf("persist removal: %w", err)
	}

	// Send snapshot to serialized change channel
	r.notifyChange()
	r.mu.Unlock()

	return nil
}

// List returns a copy of all accounts.
func (r *AccountRegistry) List() []Account {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Account, len(r.accounts))
	copy(result, r.accounts)
	return result
}

// Has returns true if an account with the given name exists.
func (r *AccountRegistry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.Name == name {
			return true
		}
	}
	return false
}

// Names returns a list of all account names.
func (r *AccountRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, len(r.accounts))
	for i, acct := range r.accounts {
		names[i] = acct.Name
	}
	return names
}

// UpdateProxy sets the proxy URL for the named account.
func (r *AccountRegistry) UpdateProxy(name, proxy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, acct := range r.accounts {
		if acct.Name == name {
			r.accounts[i].Proxy = proxy
			if err := r.save(); err != nil {
				r.accounts[i].Proxy = acct.Proxy // roll back
				return fmt.Errorf("persist proxy update: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("account %q not found", name)
}

// GetProxy returns the proxy URL for the named account, or "" if not found.
func (r *AccountRegistry) GetProxy(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.Name == name {
			return acct.Proxy
		}
	}
	return ""
}

// SetOnChange registers a callback that is invoked whenever the account list
// changes. Notifications are serialized through a channel so that rapid
// Add/Remove calls cannot cause an older snapshot to overwrite a newer one.
func (r *AccountRegistry) SetOnChange(fn func([]Account)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onChange = fn
	r.changeCh = make(chan []Account, 1)
	go func() {
		for snapshot := range r.changeCh {
			fn(snapshot)
		}
	}()
}

// notifyChange sends the current account snapshot to the change channel.
// Must be called under write lock.
func (r *AccountRegistry) notifyChange() {
	if r.changeCh == nil {
		return
	}
	snapshot := make([]Account, len(r.accounts))
	copy(snapshot, r.accounts)
	// Drain stale snapshot, then send latest
	select {
	case <-r.changeCh:
	default:
	}
	r.changeCh <- snapshot
}

func (r *AccountRegistry) save() error {
	data, err := json.MarshalIndent(r.accounts, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal accounts: %w", err)
	}
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return fileutil.AtomicWriteFile(r.path, data, 0o600)
}

func (r *AccountRegistry) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read accounts file: %w", err)
	}
	var accounts []Account
	if err := json.Unmarshal(data, &accounts); err != nil {
		return fmt.Errorf("parse accounts file: %w", err)
	}
	r.accounts = accounts
	return nil
}
