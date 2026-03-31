package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/binn/ccproxy/internal/notify"
)

func TestHandleNotifyConfig_GET_MasksToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	// Pre-save config so GET returns data
	if err := notify.SaveConfig(h.dataDir, notify.NotifyConfig{
		BotToken:       "bot:token1234",
		ChatID:         "-100999",
		EnableDisabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/notify/config", nil)
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var result map[string]interface{}
	json.NewDecoder(w.Body).Decode(&result)
	token, _ := result["bot_token"].(string)
	if !strings.HasPrefix(token, "****") {
		t.Errorf("bot_token should be masked, got %q", token)
	}
	if !strings.HasSuffix(token, "1234") {
		t.Errorf("masked token should end with last 4 chars, got %q", token)
	}
	if result["chat_id"] != "-100999" {
		t.Errorf("chat_id should be preserved, got %v", result["chat_id"])
	}
}

func TestHandleNotifyConfig_GET_EmptyConfig(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/api/notify/config", nil)
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHandleNotifyConfig_POST_SavesConfig(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	body := map[string]interface{}{
		"bot_token":       "new-bot-token",
		"chat_id":         "-100111",
		"enable_disabled": true,
		"enable_anomaly":  false,
	}
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/notify/config", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	loaded, err := notify.LoadConfig(h.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BotToken != "new-bot-token" {
		t.Errorf("token not saved, got %q", loaded.BotToken)
	}
	if loaded.ChatID != "-100111" {
		t.Errorf("chat_id not saved, got %q", loaded.ChatID)
	}
	if !loaded.EnableDisabled {
		t.Error("enable_disabled should be true")
	}
}

func TestHandleNotifyConfig_POST_PreservesMaskedToken(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	// Pre-save a token
	notify.SaveConfig(h.dataDir, notify.NotifyConfig{BotToken: "secret-token", ChatID: "-1"})

	// POST with masked token (user didn't change it)
	body := map[string]interface{}{
		"bot_token": "****oken",
		"chat_id":   "-1",
	}
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/notify/config", bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandleNotifyConfig(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	loaded, _ := notify.LoadConfig(h.dataDir)
	if loaded.BotToken != "secret-token" {
		t.Errorf("original token should be preserved, got %q", loaded.BotToken)
	}
}

func TestHandleNotifyTest_NoConfig(t *testing.T) {
	t.Parallel()
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/api/notify/test", nil)
	w := httptest.NewRecorder()
	h.HandleNotifyTest(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 when not configured, got %d", w.Code)
	}
}
