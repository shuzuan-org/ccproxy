package notify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/binn/ccproxy/internal/fileutil"
)

// NotifyConfig holds Telegram notification settings.
type NotifyConfig struct {
	BotToken       string `json:"bot_token"`
	ChatID         string `json:"chat_id"`
	EnableDisabled bool   `json:"enable_disabled"` // CategoryDisabled events
	EnableAnomaly  bool   `json:"enable_anomaly"`  // CategoryAnomaly events
}

// safeUsername matches only alphanumeric, underscore, and hyphen characters.
var safeUsername = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// configFileName returns the per-user notify config filename.
// It rejects usernames containing path separators or other unsafe characters.
func configFileName(username string) (string, error) {
	if !safeUsername.MatchString(username) {
		return "", fmt.Errorf("invalid username %q: must match [a-zA-Z0-9_-]+", username)
	}
	return "notify_" + username + ".json", nil
}

// LoadConfig reads NotifyConfig from dataDir/notify_<username>.json.
// Returns an empty config (not an error) if the file does not exist.
func LoadConfig(dataDir, username string) (NotifyConfig, error) {
	fname, err := configFileName(username)
	if err != nil {
		return NotifyConfig{}, err
	}
	path := filepath.Join(dataDir, fname)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return NotifyConfig{}, nil
	}
	if err != nil {
		return NotifyConfig{}, err
	}
	var cfg NotifyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return NotifyConfig{}, err
	}
	return cfg, nil
}

// SaveConfig writes cfg to dataDir/notify_<username>.json atomically with 0600 permissions.
func SaveConfig(dataDir, username string, cfg NotifyConfig) error {
	fname, err := configFileName(username)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(filepath.Join(dataDir, fname), data, 0600)
}

// MigrateOldConfig migrates the legacy notify.json to notify_admin.json.
// Returns true if migration was performed.
func MigrateOldConfig(dataDir string) bool {
	oldPath := filepath.Join(dataDir, "notify.json")
	fname, _ := configFileName("admin") // "admin" is always safe
	newPath := filepath.Join(dataDir, fname)

	// Skip if old file doesn't exist or new file already exists.
	if _, err := os.Stat(oldPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(newPath); err == nil {
		return false
	}

	data, err := os.ReadFile(oldPath)
	if err != nil {
		return false
	}
	if err := fileutil.AtomicWriteFile(newPath, data, 0600); err != nil {
		return false
	}
	_ = os.Remove(oldPath)
	return true
}

// ListConfigUsers scans dataDir for notify_*.json files and returns the usernames.
func ListConfigUsers(dataDir string) []string {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil
	}
	var users []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, "notify_") && strings.HasSuffix(name, ".json") {
			user := strings.TrimPrefix(name, "notify_")
			user = strings.TrimSuffix(user, ".json")
			if user != "" {
				users = append(users, user)
			}
		}
	}
	return users
}
