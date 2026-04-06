package notify

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestLoadConfigMissingFile(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig(t.TempDir(), "admin")
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
	if err := SaveConfig(dir, "admin", want); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	got, err := LoadConfig(dir, "admin")
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
	if err := SaveConfig(dir, "alice", NotifyConfig{BotToken: "x", ChatID: "y"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "notify_alice.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file perm: got %o, want 0600", perm)
	}
}

func TestSaveAndLoadConfig_PerUser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	adminCfg := NotifyConfig{BotToken: "admin-token", ChatID: "-1", EnableDisabled: true, EnableAnomaly: true}
	aliceCfg := NotifyConfig{BotToken: "alice-token", ChatID: "-2", EnableDisabled: true}

	_ = SaveConfig(dir, "admin", adminCfg)
	_ = SaveConfig(dir, "alice", aliceCfg)

	gotAdmin, _ := LoadConfig(dir, "admin")
	gotAlice, _ := LoadConfig(dir, "alice")

	if gotAdmin.BotToken != "admin-token" {
		t.Errorf("admin config wrong: %+v", gotAdmin)
	}
	if gotAlice.BotToken != "alice-token" {
		t.Errorf("alice config wrong: %+v", gotAlice)
	}
}

func TestListConfigUsers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	_ = SaveConfig(dir, "admin", NotifyConfig{BotToken: "t", ChatID: "c"})
	_ = SaveConfig(dir, "alice", NotifyConfig{BotToken: "t", ChatID: "c"})

	users := ListConfigUsers(dir)
	sort.Strings(users)
	if len(users) != 2 || users[0] != "admin" || users[1] != "alice" {
		t.Errorf("expected [admin, alice], got %v", users)
	}
}

func TestMigrateOldConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// Write old-style notify.json
	oldPath := filepath.Join(dir, "notify.json")
	os.WriteFile(oldPath, []byte(`{"bot_token":"old","chat_id":"-1"}`), 0600)

	migrated := MigrateOldConfig(dir)
	if !migrated {
		t.Fatal("expected migration to occur")
	}

	// Old file should be gone
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Error("old notify.json should be removed after migration")
	}

	// New file should exist
	cfg, err := LoadConfig(dir, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BotToken != "old" {
		t.Errorf("migrated config wrong: %+v", cfg)
	}

	// Second migration should be no-op
	if MigrateOldConfig(dir) {
		t.Error("second migration should be no-op")
	}
}
