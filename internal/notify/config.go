package notify

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/binn/ccproxy/internal/fileutil"
)

const configFileName = "notify.json"

// NotifyConfig holds Telegram notification settings.
type NotifyConfig struct {
	BotToken       string `json:"bot_token"`
	ChatID         string `json:"chat_id"`
	EnableDisabled bool   `json:"enable_disabled"` // CategoryDisabled events
	EnableAnomaly  bool   `json:"enable_anomaly"`  // CategoryAnomaly events
}

// LoadConfig reads NotifyConfig from dataDir/notify.json.
// Returns an empty config (not an error) if the file does not exist.
func LoadConfig(dataDir string) (NotifyConfig, error) {
	path := filepath.Join(dataDir, configFileName)
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

// SaveConfig writes cfg to dataDir/notify.json atomically with 0600 permissions.
func SaveConfig(dataDir string, cfg NotifyConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.AtomicWriteFile(filepath.Join(dataDir, configFileName), data, 0600)
}
