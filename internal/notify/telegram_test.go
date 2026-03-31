package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeTelegramServer(t *testing.T, wantChatID string, responses []int) (*httptest.Server, *int) {
	t.Helper()
	callCount := new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*callCount++
		idx := *callCount - 1
		statusCode := http.StatusOK
		if idx < len(responses) {
			statusCode = responses[idx]
		}
		if wantChatID != "" {
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["chat_id"] != wantChatID {
				t.Errorf("chat_id: got %q, want %q", body["chat_id"], wantChatID)
			}
		}
		w.WriteHeader(statusCode)
		w.Write([]byte(`{"ok":true}`))
	}))
	return srv, callCount
}

func newTestTelegramNotifier(srv *httptest.Server) *TelegramNotifier {
	n := NewTelegramNotifier(NotifyConfig{
		BotToken:       "test-token",
		ChatID:         "-100123",
		EnableDisabled: true,
		EnableAnomaly:  true,
	})
	n.baseURL = srv.URL
	n.client = srv.Client()
	return n
}

func TestTelegramNotifier_SendsMessage(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "-100123", []int{200})
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	err := n.Notify(context.Background(), Event{
		AccountName: "acct1",
		Type:        EventRateLimited,
		Detail:      "cooldown: 30s",
	})
	if err != nil {
		t.Fatalf("Notify: %v", err)
	}
	if *count != 1 {
		t.Errorf("expected 1 HTTP call, got %d", *count)
	}
}

func TestTelegramNotifier_CategoryDisabledFilter(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "", nil)
	defer srv.Close()

	n := NewTelegramNotifier(NotifyConfig{
		BotToken:       "tok",
		ChatID:         "-1",
		EnableDisabled: false, // disabled category OFF
		EnableAnomaly:  true,
	})
	n.baseURL = srv.URL
	n.client = srv.Client()

	// Disabled event → suppressed
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventAccountBanned})
	if *count != 0 {
		t.Errorf("expected 0 calls for suppressed category, got %d", *count)
	}

	// Anomaly event → sent
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventRateLimited})
	if *count != 1 {
		t.Errorf("expected 1 call for anomaly, got %d", *count)
	}
}

func TestTelegramNotifier_CategoryAnomalyFilter(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "", nil)
	defer srv.Close()

	n := NewTelegramNotifier(NotifyConfig{
		BotToken:       "tok",
		ChatID:         "-1",
		EnableDisabled: true,
		EnableAnomaly:  false, // anomaly category OFF
	})
	n.baseURL = srv.URL
	n.client = srv.Client()

	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventOverloaded})
	if *count != 0 {
		t.Errorf("expected 0 calls for suppressed anomaly, got %d", *count)
	}
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventAccountDisabled})
	if *count != 1 {
		t.Errorf("expected 1 call for disabled, got %d", *count)
	}
}

func TestTelegramNotifier_Dedup(t *testing.T) {
	t.Parallel()
	srv, count := makeTelegramServer(t, "", nil)
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventRateLimited})
	_ = n.Notify(context.Background(), Event{AccountName: "a", Type: EventRateLimited})
	if *count != 1 {
		t.Errorf("expected 1 call (dedup), got %d", *count)
	}
}

func TestTelegramNotifier_MessageContainsAccount(t *testing.T) {
	t.Parallel()
	var receivedText string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		json.NewDecoder(r.Body).Decode(&body)
		receivedText = body["text"]
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	_ = n.Notify(context.Background(), Event{
		AccountName: "my-account",
		Type:        EventAccountBanned,
		Detail:      "reason: platform_forbidden",
	})
	if !strings.Contains(receivedText, "my-account") {
		t.Errorf("message should contain account name, got: %q", receivedText)
	}
	if !strings.Contains(receivedText, "🔴") {
		t.Errorf("disabled event message should contain 🔴, got: %q", receivedText)
	}
}

func TestTelegramNotifier_UpstreamError(t *testing.T) {
	t.Parallel()
	srv, _ := makeTelegramServer(t, "", []int{500})
	defer srv.Close()

	n := newTestTelegramNotifier(srv)
	err := n.Notify(context.Background(), Event{AccountName: "a", Type: EventOverloaded})
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestFormatMessage_DisabledIcon(t *testing.T) {
	t.Parallel()
	msg := formatMessage(Event{AccountName: "a", Type: EventAccountDisabled, Detail: "x"})
	if !strings.HasPrefix(msg, "🔴") {
		t.Errorf("disabled event should start with 🔴, got: %q", msg)
	}
	if !strings.Contains(msg, time.Now().UTC().Format("2006-01-02")) {
		t.Errorf("message should contain today's date")
	}
}

func TestFormatMessage_AnomalyIcon(t *testing.T) {
	t.Parallel()
	msg := formatMessage(Event{AccountName: "a", Type: EventRateLimited, Detail: "x"})
	if !strings.HasPrefix(msg, "⚠️") {
		t.Errorf("anomaly event should start with ⚠️, got: %q", msg)
	}
}
