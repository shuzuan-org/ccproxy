package notify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigMissingFile(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(t.TempDir())
	if err != nil {
		t.Fatalf("expected nil for missing file, got %v", err)
	}
	if cfg.BotToken != "" || cfg.ChatID != "" {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	want := NotifyConfig{
		BotToken:       "bot123:token",
		ChatID:         "-1001234567890",
		EnableDisabled: true,
		EnableAnomaly:  true,
	}
	if err := SaveConfig(dir, want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := LoadConfig(dir)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestSaveConfigPermissions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := SaveConfig(dir, NotifyConfig{BotToken: "x", ChatID: "y"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "notify.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file perm: got %o, want 0600", perm)
	}
}
