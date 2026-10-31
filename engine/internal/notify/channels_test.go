package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

/* ===== Telegram ===== */

// rewrite направляет запросы к api.telegram.org на тестовый сервер.
type rewrite struct{ target string }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u := *req.URL
	u.Scheme = "http"
	u.Host = strings.TrimPrefix(r.target, "http://")
	req2 := req.Clone(req.Context())
	req2.URL = &u
	req2.Host = u.Host
	return http.DefaultTransport.RoundTrip(req2)
}

func telegramFor(srv *httptest.Server) *Telegram {
	tg := NewTelegram("123:ABC", "-100500")
	tg.http = &http.Client{Transport: rewrite{srv.URL}, Timeout: 5 * time.Second}
	return tg
}

func TestNewTelegramRequiresTokenAndChat(t *testing.T) {
	if NewTelegram("", "1") != nil || NewTelegram("t", "") != nil {
		t.Fatal("без токена или chat_id канала нет (nil — канал выключен)")
	}
	tg := NewTelegram("t", "1")
	if tg == nil || tg.limit == nil || tg.http == nil {
		t.Fatal("канал с лимитером и http-клиентом")
	}
}

func TestTelegramSendOK(t *testing.T) {
	var got struct {
		ChatID  string `json:"chat_id"`
		Text    string `json:"text"`
		Preview bool   `json:"disable_web_page_preview"`
	}
	var path, ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ctype = r.URL.Path, r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tg := telegramFor(srv)
	if err := tg.Send(context.Background(), "INC-1 · HIGH · проба"); err != nil {
		t.Fatal(err)
	}
	if path != "/bot123:ABC/sendMessage" || ctype != "application/json" {
		t.Fatalf("путь Bot API с токеном и JSON: %s %s", path, ctype)
	}
	if got.ChatID != "-100500" || got.Text != "INC-1 · HIGH · проба" || !got.Preview {
		t.Fatalf("тело: %+v", got)
	}
}

func TestTelegramRetriesThenSucceeds(t *testing.T) {
	// Первая попытка — 502, вторая — 200: Send повторяет (пауза 2 с) и возвращает nil.
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&n, 1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	tg := telegramFor(srv)
	start := time.Now()
	if err := tg.Send(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&n) != 2 {
		t.Fatalf("две попытки, got %d", n)
	}
	if el := time.Since(start); el < 2*time.Second || el > 4*time.Second {
		t.Fatalf("пауза перед второй попыткой ≈2 с, прошло %s", el)
	}
}

func TestTelegramCancelStopsRetries(t *testing.T) {
	// 429 — ошибка со статусом; отменённый контекст прерывает ожидание: ошибка — отмена (errors.Is), причина последней попытки в тексте.
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&n, 1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	tg := telegramFor(srv)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := tg.Send(ctx, "x")
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "telegram: 429") {
		t.Fatalf("отмена контекста с причиной последней попытки: %v", err)
	}
	if atomic.LoadInt32(&n) != 1 || time.Since(start) > time.Second {
		t.Fatalf("после отмены контекста повторов нет: попыток %d, %s", n, time.Since(start))
	}
}

func TestTelegramTransportErrorSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // соединение отказано
	tg := telegramFor(srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := tg.Send(ctx, "x"); err == nil {
		t.Fatal("сетевая ошибка возвращается")
	}
}

func TestTelegramRateLimit(t *testing.T) {
	var n int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&n, 1) }))
	defer srv.Close()
	tg := telegramFor(srv)
	tg.SetLimit(2)
	for i := 0; i < 2; i++ {
		if err := tg.Send(context.Background(), "x"); err != nil {
			t.Fatal(err)
		}
	}
	if err := tg.Send(context.Background(), "x"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("третье в ту же секунду — ErrRateLimited, got %v", err)
	}
	if atomic.LoadInt32(&n) != 2 {
		t.Fatalf("сверх лимита в сеть не ходим: %d запросов", n)
	}
	tg.limit = nil // лимитер отключён — отправка без ограничений
	if err := tg.Send(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
}

/* ===== Email ===== */

// smtpFake — минимальный SMTP-сервер: принимает одну сессию и записывает
// команды и тело письма. AUTH PLAIN объявляется, если auth=true.
type smtpFake struct {
	ln   net.Listener
	auth bool
	got  chan smtpSession
}

type smtpSession struct {
	cmds []string
	body string
}

func newSMTP(t *testing.T, auth bool) *smtpFake {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpFake{ln: ln, auth: auth, got: make(chan smtpSession, 1)}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *smtpFake) addr() (string, int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func (s *smtpFake) serve() {
	conn, err := s.ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	w("220 fake ESMTP")
	var sess smtpSession
	inData := false
	var body strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				sess.body = body.String()
				w("250 queued")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}
		sess.cmds = append(sess.cmds, line)
		switch {
		case strings.HasPrefix(line, "EHLO"):
			if s.auth {
				w("250-fake")
				w("250 AUTH PLAIN")
			} else {
				w("250 fake")
			}
		case strings.HasPrefix(line, "AUTH PLAIN"):
			w("235 ok")
		case strings.HasPrefix(line, "DATA"):
			inData = true
			w("354 go")
		case strings.HasPrefix(line, "QUIT"):
			w("221 bye")
			s.got <- sess
			return
		default:
			w("250 ok")
		}
	}
	s.got <- sess
}

func TestNewEmailRequiresFields(t *testing.T) {
	if NewEmail("", 25, "a@x", "", "", []string{"b@x"}, false) != nil ||
		NewEmail("h", 25, "", "", "", []string{"b@x"}, false) != nil ||
		NewEmail("h", 25, "a@x", "", "", nil, false) != nil {
		t.Fatal("без хоста, отправителя или получателей канала нет")
	}
	e := NewEmail("h", 0, "a@x", "", "", []string{"b@x"}, true)
	if e == nil || e.Port != 587 || e.limit == nil || !e.StartTLS {
		t.Fatalf("порт по умолчанию 587, лимитер включён: %+v", e)
	}
}

func TestEmailSendPlain(t *testing.T) {
	srv := newSMTP(t, false)
	host, port := srv.addr()
	e := NewEmail(host, port, "argus@example.org", "", "", []string{"soc@example.org", "duty@example.org"}, false)
	if err := e.Send(context.Background(), "INC-1 · HIGH", "тело\nвторая строка"); err != nil {
		t.Fatal(err)
	}
	var sess smtpSession
	select {
	case sess = <-srv.got:
	case <-time.After(3 * time.Second):
		t.Fatal("сессия не завершилась QUIT")
	}
	joined := strings.Join(sess.cmds, "\n")
	for _, want := range []string{"MAIL FROM:<argus@example.org>", "RCPT TO:<soc@example.org>", "RCPT TO:<duty@example.org>", "DATA", "QUIT"} {
		if !strings.Contains(joined, want) {
			t.Errorf("нет команды %q в %q", want, joined)
		}
	}
	if strings.Contains(joined, "AUTH") || strings.Contains(joined, "STARTTLS") {
		t.Errorf("без пользователя и StartTLS — ни AUTH, ни STARTTLS: %q", joined)
	}
	for _, want := range []string{"From: argus@example.org", "To: soc@example.org, duty@example.org", "Subject: INC-1 · HIGH", "Content-Type: text/plain; charset=utf-8", "тело", "вторая строка"} {
		if !strings.Contains(sess.body, want) {
			t.Errorf("нет %q в письме %q", want, sess.body)
		}
	}
}

func TestEmailSendAuth(t *testing.T) {
	// PlainAuth без TLS допускается только к localhost — ровно наш случай с relay на 127.0.0.1.
	srv := newSMTP(t, true)
	host, port := srv.addr()
	e := NewEmail(host, port, "argus@example.org", "argus", "секрет", []string{"soc@example.org"}, false)
	if err := e.Send(context.Background(), "s", "b"); err != nil {
		t.Fatal(err)
	}
	sess := <-srv.got
	if !strings.Contains(strings.Join(sess.cmds, "\n"), "AUTH PLAIN") {
		t.Fatalf("с пользователем — AUTH PLAIN: %v", sess.cmds)
	}
}

func TestEmailSendStartTLSRefused(t *testing.T) {
	// Сервер не объявляет STARTTLS — Send с StartTLS=true возвращает ошибку, письмо не уходит.
	srv := newSMTP(t, false)
	host, port := srv.addr()
	e := NewEmail(host, port, "argus@example.org", "", "", []string{"soc@example.org"}, true)
	if err := e.Send(context.Background(), "s", "b"); err == nil {
		t.Fatal("STARTTLS не поддержан сервером — ошибка, а не отправка открытым текстом")
	}
}

func TestEmailSendClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := ln.Addr().(*net.TCPAddr)
	ln.Close()
	e := NewEmail(a.IP.String(), a.Port, "a@x", "", "", []string{"b@x"}, false)
	start := time.Now()
	if err := e.Send(context.Background(), "s", "b"); err == nil {
		t.Fatal("закрытый порт — ошибка dial")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("отказ соединения должен приходить сразу, ждали %s", time.Since(start))
	}
}

func TestEmailSendContextCancelled(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() // слушаем, но не отвечаем приветствием
	a := ln.Addr().(*net.TCPAddr)
	e := NewEmail(a.IP.String(), a.Port, "a@x", "", "", []string{"b@x"}, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Send(ctx, "s", "b"); err == nil {
		t.Fatal("отменённый контекст — ошибка на dial")
	}
}

func TestEmailRateLimit(t *testing.T) {
	e := NewEmail("127.0.0.1", 1, "a@x", "", "", []string{"b@x"}, false)
	e.SetLimit(1)
	// Первое письмо пройдёт лимитер и упадёт на dial (порт 1 закрыт), второе — отброшено лимитером без dial.
	if err := e.Send(context.Background(), "s", "b"); err == nil || errors.Is(err, ErrRateLimited) {
		t.Fatalf("первое — ошибка сети, не лимита: %v", err)
	}
	if err := e.Send(context.Background(), "s", "b"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("второе в ту же секунду — ErrRateLimited: %v", err)
	}
}

/* ===== Aggregator ===== */

func TestNewAggregatorDefaults(t *testing.T) {
	a := NewAggregator(0, 0)
	if a.window != time.Minute || a.limit != 5 {
		t.Fatalf("окно 1m и лимит 5 по умолчанию: %s %d", a.window, a.limit)
	}
	a = NewAggregator(-time.Second, -1)
	if a.window != time.Minute || a.limit != 5 {
		t.Fatal("отрицательные — тоже по умолчанию")
	}
}

func TestAggregatorBelowLimitNoSummary(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 3)
	a.nowFn = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if !a.Add("r1", "t", "10.0.0.1") {
			t.Fatal("в пределах лимита — отдельно")
		}
	}
	now = now.Add(2 * time.Minute)
	if out := a.Flush(); len(out) != 0 {
		t.Fatalf("все ушли отдельно — сводки нет: %v", out)
	}
	if len(a.rules) != 0 {
		t.Fatal("закрытое окно удалено")
	}
}

func TestAggregatorAddressesDedupAndCap(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 1)
	a.nowFn = func() time.Time { return now }
	a.Add("r1", "Brute", "203.0.113.1")
	for i := 0; i < 5; i++ {
		a.Add("r1", "Brute", "203.0.113.1") // дубликаты одного адреса
		a.Add("r1", "Brute", " 203.0.113.1 ")
	}
	a.Add("r1", "Brute", "") // пустой адрес не считается
	for i := 2; i <= 14; i++ {
		a.Add("r1", "Brute", "203.0.113."+strconv.Itoa(i)) // ещё 13 разных: в списке максимум 10
	}
	now = now.Add(time.Minute)
	out := a.Flush()
	if len(out) != 1 {
		t.Fatalf("одна сводка: %v", out)
	}
	s := out[0]
	if !strings.Contains(s, "25 инцидентов по правилу «Brute» (r1)") || !strings.Contains(s, "из них 1 показаны отдельно") {
		t.Fatalf("счётчики: %s", s)
	}
	if strings.Count(s, "203.0.113.") != 10 || !strings.Contains(s, "и ещё 4") {
		t.Fatalf("адресов не больше 10, остаток числом (14 уникальных): %s", s)
	}
}

func TestAggregatorNoAddresses(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 1)
	a.nowFn = func() time.Time { return now }
	a.Add("r1", "Silence", "")
	a.Add("r1", "Silence", "")
	now = now.Add(time.Minute)
	out := a.Flush()
	if len(out) != 1 || !strings.Contains(out[0], "(адреса: —)") {
		t.Fatalf("без адресов — прочерк: %v", out)
	}
}

func TestAggregatorLateAddAfterWindowKeepsSummary(t *testing.T) {
	// Окно закрылось, Flush ещё не звали, пришёл новый инцидент: он добавляется в
	// старую сводку (иначе подавленные потерялись бы), и отдельно не уходит.
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 1)
	a.nowFn = func() time.Time { return now }
	a.Add("r1", "t", "a")
	a.Add("r1", "t", "b") // подавлен
	now = now.Add(2 * time.Minute)
	if a.Add("r1", "t", "c") {
		t.Fatal("после закрытия окна с подавленными — в сводку, не отдельно")
	}
	out := a.Flush()
	if len(out) != 1 || !strings.Contains(out[0], "3 инцидентов") || !strings.Contains(out[0], "a, b, c") {
		t.Fatalf("сводка со всеми тремя: %v", out)
	}
	// А если подавленных не было — окно просто открывается заново.
	a.Add("r2", "t", "a")
	now = now.Add(2 * time.Minute)
	if !a.Add("r2", "t", "b") {
		t.Fatal("старое окно без подавленных — новое окно, первое сообщение отдельно")
	}
}

func TestAggregatorFlushSortedByRule(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 1)
	a.nowFn = func() time.Time { return now }
	for _, id := range []string{"z-rule", "a-rule", "m-rule"} {
		a.Add(id, id, "x")
		a.Add(id, id, "y")
	}
	now = now.Add(time.Minute)
	out := a.Flush()
	if len(out) != 3 || !strings.Contains(out[0], "(a-rule)") || !strings.Contains(out[1], "(m-rule)") || !strings.Contains(out[2], "(z-rule)") {
		t.Fatalf("сводки по алфавиту правил: %v", out)
	}
	if out := a.Flush(); len(out) != 0 {
		t.Fatalf("повторный Flush пуст: %v", out)
	}
}

func TestAggregatorOpenWindowNotFlushed(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	a := NewAggregator(time.Minute, 1)
	a.nowFn = func() time.Time { return now }
	a.Add("r1", "t", "a")
	a.Add("r1", "t", "b")
	now = now.Add(59 * time.Second)
	if out := a.Flush(); len(out) != 0 {
		t.Fatalf("окно ещё открыто: %v", out)
	}
	now = now.Add(time.Second)
	if out := a.Flush(); len(out) != 1 {
		t.Fatalf("ровно по границе окна — сводка: %v", out)
	}
}
