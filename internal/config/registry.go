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
	"github.com/google/uuid"
)

// Account represents a dynamically managed backend account.
type Account struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Proxy   string `json:"proxy,omitempty"`
	Owner   string `json:"owner,omitempty"`
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

// Add adds a new account with the given name and owner. Returns the generated
// account ID or an error if the name is empty.
func (r *AccountRegistry) Add(name, owner string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("account name cannot be empty")
	}

	id := uuid.New().String()

	r.mu.Lock()

	r.accounts = append(r.accounts, Account{ID: id, Name: name, Enabled: true, Owner: owner})
	if err := r.save(); err != nil {
		// Roll back
		r.accounts = r.accounts[:len(r.accounts)-1]
		r.mu.Unlock()
		return "", fmt.Errorf("persist account: %w", err)
	}

	// Send snapshot to serialized change channel
	r.notifyChange()
	r.mu.Unlock()

	return id, nil
}

// Remove removes the account with the given ID.
func (r *AccountRegistry) Remove(id string) error {
	r.mu.Lock()

	idx := -1
	for i, acct := range r.accounts {
		if acct.ID == id {
			idx = i
			break
		}
	}
	if idx == -1 {
		r.mu.Unlock()
		return fmt.Errorf("account %q not found", id)
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

// Has returns true if an account with the given ID exists.
func (r *AccountRegistry) Has(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.ID == id {
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

// IDs returns a list of all account IDs.
func (r *AccountRegistry) IDs() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, len(r.accounts))
	for i, acct := range r.accounts {
		ids[i] = acct.ID
	}
	return ids
}

// GetByID returns the account with the given ID and true, or a zero Account and false.
func (r *AccountRegistry) GetByID(id string) (Account, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.ID == id {
			return acct, true
		}
	}
	return Account{}, false
}

// Rename changes the display name of the account with the given ID.
func (r *AccountRegistry) Rename(id, newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return errors.New("account name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for i, acct := range r.accounts {
		if acct.ID == id {
			old := r.accounts[i].Name
			r.accounts[i].Name = newName
			if err := r.save(); err != nil {
				r.accounts[i].Name = old
				return fmt.Errorf("persist rename: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("account %q not found", id)
}

// NameToIDMap returns a snapshot mapping each account name to its ID.
// Only valid during initial migration when names are still unique.
func (r *AccountRegistry) NameToIDMap() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m := make(map[string]string, len(r.accounts))
	for _, acct := range r.accounts {
		m[acct.Name] = acct.ID
	}
	return m
}

// UpdateProxy sets the proxy URL for the account with the given ID.
func (r *AccountRegistry) UpdateProxy(id, proxy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, acct := range r.accounts {
		if acct.ID == id {
			r.accounts[i].Proxy = proxy
			if err := r.save(); err != nil {
				r.accounts[i].Proxy = acct.Proxy // roll back
				return fmt.Errorf("persist proxy update: %w", err)
			}
			r.notifyChange()
			return nil
		}
	}
	return fmt.Errorf("account %q not found", id)
}

// GetProxy returns the proxy URL for the account with the given ID, or "" if not found.
func (r *AccountRegistry) GetProxy(id string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.ID == id {
			return acct.Proxy
		}
	}
	return ""
}

// ListByOwner returns a copy of accounts owned by the given owner.
func (r *AccountRegistry) ListByOwner(owner string) []Account {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []Account
	for _, acct := range r.accounts {
		if acct.Owner == owner {
			result = append(result, acct)
		}
	}
	return result
}

// IsOwner returns true if the account with the given ID exists and is owned by owner.
func (r *AccountRegistry) IsOwner(accountID, owner string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.ID == accountID {
			return acct.Owner == owner
		}
	}
	return false
}

// GetOwner returns the owner of the account with the given ID, or "" if not found.
func (r *AccountRegistry) GetOwner(accountID string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, acct := range r.accounts {
		if acct.ID == accountID {
			return acct.Owner
		}
	}
	return ""
}

// MigrateOwnerless assigns the given owner to all accounts that have an empty owner.
// Returns the number of accounts migrated.
func (r *AccountRegistry) MigrateOwnerless(owner string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	count := 0
	for i := range r.accounts {
		if r.accounts[i].Owner == "" {
			r.accounts[i].Owner = owner
			count++
		}
	}
	if count > 0 {
		if err := r.save(); err != nil {
			slog.Error("registry: failed to persist owner migration", "error", err.Error())
			return 0
		}
		slog.Info("registry: migrated ownerless accounts", "owner", owner, "count", count)
	}
	return count
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

	// Auto-migrate: assign UUIDs to accounts that lack an ID
	migrated := 0
	for i := range r.accounts {
		if r.accounts[i].ID == "" {
			r.accounts[i].ID = uuid.New().String()
			migrated++
		}
	}
	if migrated > 0 {
		if err := r.save(); err != nil {
			return fmt.Errorf("persist id migration: %w", err)
		}
		slog.Info("registry: migrated accounts to UUID", "count", migrated)
	}

	return nil
}
