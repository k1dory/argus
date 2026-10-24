package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// newHTTPClient — без редиректов: токен не должен уйти на другой хост.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// statusError — 2xx — nil; 4xx, кроме 408/429, и 3xx — постоянная ошибка; остальное — повтор.
func statusError(target string, resp *http.Response) error {
	if resp.StatusCode/100 == 2 {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	// Тело ответа — чужие данные: в лог только в кавычках, без управляющих символов.
	err := fmt.Errorf("%s: HTTP %d: %q", target, resp.StatusCode, safeText(strings.TrimSpace(strings.ToValidUTF8(string(body), "?")), 200))
	switch {
	case resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests:
		return err
	case resp.StatusCode >= 300 && resp.StatusCode < 500:
		return &PermanentError{Err: err}
	}
	return err
}

// Sign — подпись тела: "sha256=" + hex(HMAC-SHA256(secret, body)).
func Sign(secret string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

/* ===== HTTP-вебхук ===== */

// HTTPTarget — JSON-POST события на произвольный адрес. Подпись HMAC-SHA256
// тела — в X-Argus-Signature (если задан секрет), токен — в Authorization.
// Дедуп — по инциденту и типу события: эскалация уже известного инцидента
// получателю интересна, повтор того же события — нет.
type HTTPTarget struct {
	Name   string
	URL    string
	Secret string
	Token  string
	HTTP   *http.Client
}

func (t *HTTPTarget) DedupKey(p Payload) string { return p.Incident.ID + "|" + p.Event }

func (t *HTTPTarget) Deliver(ctx context.Context, p Payload, _ Record, _ func(string) error) (string, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return "", &PermanentError{Err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return "", &PermanentError{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "argus-engine")
	req.Header.Set("X-Argus-Event", p.Event)
	req.Header.Set("X-Argus-Delivery", p.DeliveryID)
	if t.Secret != "" {
		req.Header.Set("X-Argus-Signature", Sign(t.Secret, body))
	}
	if t.Token != "" {
		req.Header.Set("Authorization", "Bearer "+t.Token)
	}
	resp, err := t.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", t.Name, scrubURL(err))
	}
	defer resp.Body.Close()
	if err := statusError(t.Name, resp); err != nil {
		return "", err
	}
	return strconv.Itoa(resp.StatusCode), nil
}

// scrubURL — url.Error печатает адрес целиком (с query, где бывает токен);
// в лог идёт только причина.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// safeText — свободный текст чужого происхождения (тело ответа цели):
// управляющие символы и переводы строк → пробел, длина не больше max рун,
// чтобы строка лога не подделывала соседние записи.
func safeText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}
