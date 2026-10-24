// Package notify — уведомления дежурному. Telegram: токен только из
// окружения, в конфиг попадает лишь chat_id.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Telegram struct {
	Token  string
	ChatID string
	http   *http.Client
	limit  *Limiter // 20 сообщений в минуту: лимит Bot API на чат и защита от шторма
}

func NewTelegram(token, chatID string) *Telegram {
	if token == "" || chatID == "" {
		return nil
	}
	return &Telegram{Token: token, ChatID: chatID, http: &http.Client{Timeout: 10 * time.Second}, limit: NewLimiter(20)}
}

// SetLimit — сообщений в минуту (по умолчанию 20).
func (t *Telegram) SetLimit(perMinute int) { t.limit = NewLimiter(perMinute) }

// Send — до трёх попыток с паузой: Telegram иногда отвечает 429/5xx.
// Сверх лимита — ErrRateLimited без попыток отправки.
func (t *Telegram) Send(ctx context.Context, text string) error {
	if t.limit != nil && !t.limit.Allow() {
		return ErrRateLimited
	}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = t.sendOnce(ctx, text); err == nil {
			return nil
		}
		select {
		case <-time.After(time.Duration(attempt+1) * 2 * time.Second):
		case <-ctx.Done():
			return err
		}
	}
	return err
}

func (t *Telegram) sendOnce(ctx context.Context, text string) error {
	body, _ := json.Marshal(map[string]any{"chat_id": t.ChatID, "text": text, "disable_web_page_preview": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+t.Token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram: %s", resp.Status)
	}
	return nil
}
