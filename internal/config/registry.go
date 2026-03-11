package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Instance represents a dynamically managed backend instance.
type Instance struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// InstanceRegistry manages a persistent list of instances stored in data/instances.json.
type InstanceRegistry struct {
	mu        sync.RWMutex
	path      string
	instances []Instance
	onChange  func([]Instance)
}

// NewInstanceRegistry creates or loads an InstanceRegistry from the given data directory.
func NewInstanceRegistry(dataDir string) *InstanceRegistry {
	path := filepath.Join(dataDir, "instances.json")
	r := &InstanceRegistry{path: path}
	_ = r.load() // ignore error on first run (file may not exist)
	return r
}

// Add adds a new instance with the given name. Returns an error if the name
// is empty, contains invalid characters, or is already taken.
func (r *InstanceRegistry) Add(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("instance name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, inst := range r.instances {
		if inst.Name == name {
			return fmt.Errorf("instance %q already exists", name)
		}
	}

	r.instances = append(r.instances, Instance{Name: name, Enabled: true})
	if err := r.save(); err != nil {
		// Roll back
		r.instances = r.instances[:len(r.instances)-1]
		return fmt.Errorf("persist instance: %w", err)
	}

	if r.onChange != nil {
		// Copy to avoid data race with callback
		snapshot := make([]Instance, len(r.instances))
		copy(snapshot, r.instances)
		go r.onChange(snapshot)
	}
	return nil
}

// Remove removes the instance with the given name.
func (r *InstanceRegistry) Remove(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	idx := -1
	for i, inst := range r.instances {
		if inst.Name == name {
			idx = i
			break
		}
	}
	if idx == -1 {
		return fmt.Errorf("instance %q not found", name)
	}

	removed := r.instances[idx]
	r.instances = append(r.instances[:idx], r.instances[idx+1:]...)
	if err := r.save(); err != nil {
		// Roll back
		r.instances = append(r.instances[:idx], append([]Instance{removed}, r.instances[idx:]...)...)
		return fmt.Errorf("persist removal: %w", err)
	}

	if r.onChange != nil {
		snapshot := make([]Instance, len(r.instances))
		copy(snapshot, r.instances)
		go r.onChange(snapshot)
	}
	return nil
}

// List returns a copy of all instances.
func (r *InstanceRegistry) List() []Instance {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Instance, len(r.instances))
	copy(result, r.instances)
	return result
}

// Has returns true if an instance with the given name exists.
func (r *InstanceRegistry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, inst := range r.instances {
		if inst.Name == name {
			return true
		}
	}
	return false
}

// Names returns a list of all instance names.
func (r *InstanceRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, len(r.instances))
	for i, inst := range r.instances {
		names[i] = inst.Name
	}
	return names
}

// SetOnChange registers a callback that is invoked (in a goroutine) whenever
// the instance list changes.
func (r *InstanceRegistry) SetOnChange(fn func([]Instance)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onChange = fn
}

func (r *InstanceRegistry) save() error {
	data, err := json.MarshalIndent(r.instances, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal instances: %w", err)
	}
	dir := filepath.Dir(r.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	return os.WriteFile(r.path, data, 0o600)
}

func (r *InstanceRegistry) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read instances file: %w", err)
	}
	var instances []Instance
	if err := json.Unmarshal(data, &instances); err != nil {
		return fmt.Errorf("parse instances file: %w", err)
	}
	r.instances = instances
	return nil
}
