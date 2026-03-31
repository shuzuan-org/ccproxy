package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

const (
	telegramAPIBase = "https://api.telegram.org"
	dedupTTL        = 5 * time.Minute
	httpTimeout     = 10 * time.Second
)

// TelegramNotifier sends notifications via Telegram Bot API sendMessage.
type TelegramNotifier struct {
	cfg     NotifyConfig
	client  *http.Client
	dedup   *Dedup
	baseURL string // overridable for testing
}

// NewTelegramNotifier creates a TelegramNotifier from cfg.
func NewTelegramNotifier(cfg NotifyConfig) *TelegramNotifier {
	return &TelegramNotifier{
		cfg:     cfg,
		client:  &http.Client{Timeout: httpTimeout},
		dedup:   NewDedup(dedupTTL),
		baseURL: telegramAPIBase,
	}
}

// Notify sends an event if the category is enabled and not suppressed by dedup.
// Errors are logged as warnings; callers can ignore the returned error.
func (t *TelegramNotifier) Notify(ctx context.Context, event Event) error {
	cat := event.Type.Category()
	if cat == CategoryDisabled && !t.cfg.EnableDisabled {
		return nil
	}
	if cat == CategoryAnomaly && !t.cfg.EnableAnomaly {
		return nil
	}
	if !t.dedup.Allow(event.AccountName, event.Type) {
		return nil
	}
	if err := t.sendMessage(ctx, formatMessage(event)); err != nil {
		slog.Warn("telegram notify failed",
			"account", event.AccountName,
			"event", string(event.Type),
			"err", err,
		)
		return err
	}
	return nil
}

func (t *TelegramNotifier) sendMessage(ctx context.Context, text string) error {
	url := fmt.Sprintf("%s/bot%s/sendMessage", t.baseURL, t.cfg.BotToken)
	body, _ := json.Marshal(map[string]string{
		"chat_id": t.cfg.ChatID,
		"text":    text,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API: status %d", resp.StatusCode)
	}
	return nil
}

func formatMessage(event Event) string {
	icon := "⚠️"
	if event.Type.Category() == CategoryDisabled {
		icon = "🔴"
	}
	return fmt.Sprintf(
		"%s [ccproxy] 账户异常通知\n\n账户：%s\n事件：%s\n详情：%s\n时间：%s UTC",
		icon,
		event.AccountName,
		eventTypeLabel(event.Type),
		event.Detail,
		time.Now().UTC().Format("2006-01-02 15:04:05"),
	)
}

func eventTypeLabel(e EventType) string {
	switch e {
	case EventAccountDisabled:
		return "账户被禁用 (连续401)"
	case EventAccountBanned:
		return "账户平台封禁"
	case EventRateLimited:
		return "真速率限制 (429)"
	case EventOverloaded:
		return "过载冷却 (529)"
	case EventTimeoutCooldown:
		return "超时阈值冷却"
	case EventBudgetBlocked:
		return "预算阻断 (Blocked)"
	default:
		return string(e)
	}
}
