package notify

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Email — SMTP с STARTTLS (или без TLS для локального relay). Пароль — только
// из окружения (SMTP_PASSWORD), в конфиг попадают хост, порт, адреса.
type Email struct {
	Host, From string
	Port       int
	User, Pass string
	To         []string
	StartTLS   bool
	limit      *Limiter // писем в минуту: шторм инцидентов не должен класть relay
}

func NewEmail(host string, port int, from, user, pass string, to []string, startTLS bool) *Email {
	if host == "" || from == "" || len(to) == 0 {
		return nil
	}
	if port == 0 {
		port = 587
	}
	return &Email{Host: host, Port: port, From: from, User: user, Pass: pass, To: to, StartTLS: startTLS, limit: NewLimiter(20)}
}

// SetLimit — писем в минуту (по умолчанию 20).
func (e *Email) SetLimit(perMinute int) { e.limit = NewLimiter(perMinute) }

func (e *Email) Send(ctx context.Context, subject, body string) error {
	if e.limit != nil && !e.limit.Allow() {
		return ErrRateLimited
	}
	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)
	d := net.Dialer{Timeout: 15 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	c, err := smtp.NewClient(conn, e.Host)
	if err != nil {
		return err
	}
	defer c.Close()
	if e.StartTLS {
		if err := c.StartTLS(&tls.Config{ServerName: e.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if e.User != "" {
		if err := c.Auth(smtp.PlainAuth("", e.User, e.Pass, e.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(e.From); err != nil {
		return err
	}
	for _, to := range e.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		e.From, strings.Join(e.To, ", "), subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
