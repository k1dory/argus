package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/notify"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

func TestWantsNotify(t *testing.T) {
	for _, tc := range []struct {
		levels []string
		level  string
		want   bool
	}{
		{nil, "critical", true},
		{nil, "high", false},
		{[]string{}, "Critical", true},
		{[]string{"high", "critical"}, "HIGH", true},
		{[]string{"high"}, "medium", false},
		{[]string{"LOW"}, "low", true},
	} {
		if got := wantsNotify(tc.levels, tc.level); got != tc.want {
			t.Errorf("wantsNotify(%v, %q) = %v, ожидалось %v", tc.levels, tc.level, got, tc.want)
		}
	}
}

// telegramFake — перехват api.telegram.org: клиент Telegram ходит через
// http.DefaultTransport. Подмена ставится один раз на процесс (горутины
// отправки переживают тест, и возврат транспорта давал бы гонку), текущий
// получатель переключается под мьютексом; чужие хосты идут в настоящий транспорт.
type telegramFake struct {
	mu    sync.Mutex
	texts []string
	seen  chan struct{}
}

type telegramRouter struct {
	mu      sync.Mutex
	current *telegramFake
	orig    http.RoundTripper
}

var tgRouter *telegramRouter
var tgRouterOnce sync.Once

func (r *telegramRouter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != "api.telegram.org" {
		return r.orig.RoundTrip(req)
	}
	r.mu.Lock()
	f := r.current
	r.mu.Unlock()
	if f == nil {
		return nil, fmt.Errorf("telegram fake: получатель не назначен")
	}
	var body struct {
		Text string `json:"text"`
	}
	_ = json.NewDecoder(req.Body).Decode(&body)
	f.mu.Lock()
	f.texts = append(f.texts, body.Text)
	f.mu.Unlock()
	select {
	case f.seen <- struct{}{}:
	default:
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: http.Header{}, Request: req}, nil
}

func (f *telegramFake) wait(t *testing.T, n int) []string {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-f.seen:
		case <-time.After(3 * time.Second):
			t.Fatalf("Telegram: получено %d сообщений, ожидалось %d", i, n)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.texts...)
}

func installTelegramFake(t *testing.T) *telegramFake {
	t.Helper()
	tgRouterOnce.Do(func() {
		tgRouter = &telegramRouter{orig: http.DefaultTransport}
		http.DefaultTransport = tgRouter
	})
	f := &telegramFake{seen: make(chan struct{}, 100)}
	tgRouter.mu.Lock()
	tgRouter.current = f
	tgRouter.mu.Unlock()
	return f
}

// smtpFake — минимальный SMTP: принимает сессии по одной, отдаёт тему и тело.
type smtpFake struct {
	ln  net.Listener
	got chan smtpMail
}

type smtpMail struct{ subject, body string }

func newSMTPFake(t *testing.T) *smtpFake {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &smtpFake{ln: ln, got: make(chan smtpMail, 10)}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(conn)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *smtpFake) hostPort() (string, int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func (s *smtpFake) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := func(line string) { _, _ = io.WriteString(conn, line+"\r\n") }
	w("220 fake ESMTP")
	var m smtpMail
	inData := false
	var body strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if inData {
			if line == "." {
				inData = false
				raw := body.String()
				if i := strings.Index(raw, "\n\n"); i >= 0 {
					for _, h := range strings.Split(raw[:i], "\n") {
						if strings.HasPrefix(h, "Subject: ") {
							m.subject = strings.TrimPrefix(h, "Subject: ")
						}
					}
					m.body = raw[i+2:]
				}
				w("250 queued")
				continue
			}
			body.WriteString(line + "\n")
			continue
		}
		switch {
		case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
			w("250 fake")
		case strings.HasPrefix(line, "DATA"):
			inData = true
			w("354 go")
		case strings.HasPrefix(line, "QUIT"):
			w("221 bye")
			s.got <- m
			return
		default:
			w("250 ok")
		}
	}
}

func (s *smtpFake) wait(t *testing.T) smtpMail {
	t.Helper()
	select {
	case m := <-s.got:
		return m
	case <-time.After(3 * time.Second):
		t.Fatal("письмо не пришло")
		return smtpMail{}
	}
}

func notifyEngine(t *testing.T, window time.Duration, tgLevels, mailLevels []string) (*engine, *telegramFake, *smtpFake) {
	t.Helper()
	tg := installTelegramFake(t)
	smtp := newSMTPFake(t)
	host, port := smtp.hostPort()
	acfg, _ := analyst.LoadConfig("")
	acfg.Notify.Telegram.Levels = tgLevels
	acfg.Notify.Email.Levels = mailLevels
	e := &engine{
		acfg: acfg,
		tg:   notify.NewTelegram("token", "chat"),
		mail: notify.NewEmail(host, port, "argus@test", "", "", []string{"soc@test"}, false),
		agg:  notify.NewAggregator(window, 5),
	}
	return e, tg, smtp
}

func incidentN(n int, level string) *incidents.Incident {
	return &incidents.Incident{IncidentID: fmt.Sprintf("INC-%d", n), Level: level, RuleID: "r1", RuleTitle: "Перебор SSH",
		ActorName: fmt.Sprintf("203.0.113.%d", n), EventCount: 7, Chain: []string{"10:00:00  ssh  host  login.fail  x"}}
}

func TestNotifyIncidentRespectsLevelsAndChannels(t *testing.T) {
	e, tg, smtp := notifyEngine(t, time.Minute, nil, []string{"high"})
	ctx := context.Background()

	// critical — только Telegram (почта хочет high), high — только почта.
	e.notifyIncident(ctx, incidentN(1, "critical"))
	texts := tg.wait(t, 1)
	if !strings.HasPrefix(texts[0], "⚠ INC-1 · CRITICAL · Перебор SSH") {
		t.Fatalf("текст Telegram: %q", texts[0])
	}
	e.notifyIncident(ctx, incidentN(2, "high"))
	m := smtp.wait(t)
	if m.subject != "[ARGUS] INC-2 HIGH · Перебор SSH" || !strings.Contains(m.body, "10:00:00  ssh  host  login.fail  x") {
		t.Fatalf("письмо: %+v", m)
	}
	// medium никому не нужен — ни запросов, ни подавлений.
	e.notifyIncident(ctx, incidentN(3, "medium"))
	time.Sleep(50 * time.Millisecond)
	if n := len(tg.wait(t, 0)); n != 1 {
		t.Fatalf("Telegram получил %d сообщений, ожидалось 1", n)
	}
	if e.m.notifySuppressed.Load() != 0 {
		t.Fatal("нежелательный уровень не считается подавлением")
	}
}

func TestNotifyIncidentStormGoesToDigest(t *testing.T) {
	e, tg, smtp := notifyEngine(t, 300*time.Millisecond, []string{"critical"}, []string{"critical"})
	ctx := context.Background()
	for i := 1; i <= 7; i++ {
		e.notifyIncident(ctx, incidentN(i, "critical"))
	}
	// Первые пять по правилу уходят отдельно, шестой и седьмой — в сводку.
	texts := tg.wait(t, 5)
	for i := 1; i <= 5; i++ {
		smtp.wait(t)
	}
	if e.m.notifySuppressed.Load() != 2 {
		t.Fatalf("подавлено %d, ожидалось 2", e.m.notifySuppressed.Load())
	}
	// Пока окно открыто, сводки нет.
	e.flushDigests(ctx)
	time.Sleep(20 * time.Millisecond)
	if len(tg.wait(t, 0)) != 5 {
		t.Fatal("сводка ушла до закрытия окна")
	}
	time.Sleep(350 * time.Millisecond)
	e.flushDigests(ctx)
	texts = tg.wait(t, 1)
	digest := texts[len(texts)-1]
	if !strings.Contains(digest, "7 инцидентов по правилу «Перебор SSH» (r1)") || !strings.Contains(digest, "из них 5 показаны отдельно") {
		t.Fatalf("сводка: %q", digest)
	}
	if m := smtp.wait(t); m.subject != "[ARGUS] шторм инцидентов" || m.body[:len("⚠ 7 инцидентов")] != "⚠ 7 инцидентов" {
		t.Fatalf("письмо-сводка: %+v", m)
	}
}

func TestSendTelegramRateLimitCountsSuppressed(t *testing.T) {
	e, tg, _ := notifyEngine(t, time.Minute, nil, nil)
	e.tg.SetLimit(1) // burst = 1: второе сообщение подряд отбрасывается без похода в сеть
	ctx := context.Background()
	e.sendTelegram(ctx, "a")
	tg.wait(t, 1)
	e.sendTelegram(ctx, "b")
	deadline := time.Now().Add(2 * time.Second)
	for e.m.notifySuppressed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if e.m.notifySuppressed.Load() != 1 {
		t.Fatalf("ErrRateLimited должен учитываться в notify_suppressed, got %d", e.m.notifySuppressed.Load())
	}
}

func TestSendMailFailureIsLoggedOnly(t *testing.T) {
	// Почтовый relay недоступен: ошибка только в лог, движок не падает.
	e := &engine{mail: notify.NewEmail("127.0.0.1", 1, "argus@test", "", "", []string{"soc@test"}, false)}
	e.sendMail(context.Background(), "s", "b")
	time.Sleep(50 * time.Millisecond)
	if e.m.notifySuppressed.Load() != 0 {
		t.Fatal("сетевая ошибка — не подавление")
	}
}

func TestWarnExceptionOncePerKeyAndBounded(t *testing.T) {
	e := &engine{excWarned: map[string]bool{}}
	e.warnException("r1", "attrs.x", "v")
	e.warnException("r1", "attrs.x", "v")
	if len(e.excWarned) != 1 || !e.excWarned["r1|attrs.x|v"] {
		t.Fatalf("ключ должен запоминаться один раз: %v", e.excWarned)
	}
	for i := 0; i < 1001; i++ {
		e.warnException("r1", "attrs.x", fmt.Sprint(i))
	}
	// На 1002-м ключе карта сбрасывается и начинается заново.
	if len(e.excWarned) > 1002 || len(e.excWarned) == 0 {
		t.Fatalf("карта предупреждений не ограничена: %d", len(e.excWarned))
	}
	e.excWarned = map[string]bool{}
	for i := 0; i < 1001; i++ {
		e.excWarned[fmt.Sprint(i)] = true
	}
	e.warnException("r2", "f", "v")
	if len(e.excWarned) != 1 {
		t.Fatalf("после 1000 ключей карта должна сброситься, got %d", len(e.excWarned))
	}
}

func TestAnalystLimitIncident(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	e.analystLimitIncident(context.Background(), "лимит 500 исчерпан")
	rows := f.waitRows(t, "incidents", 1)
	if !strings.Contains(rows[0], `"rule_id":"argus.system.analyst_limit"`) || !strings.Contains(rows[0], "лимит 500 исчерпан") {
		t.Fatalf("системный инцидент: %s", rows[0])
	}
	if e.m.incidentsCreated.Load() != 1 {
		t.Fatal("счётчик созданных инцидентов")
	}
	if e.reg.OpenByRule(analystLimitRuleID) == nil {
		t.Fatal("инцидент не попал в реестр")
	}
	// Хранилище отказало — в реестр не попадает, счётчик не растёт.
	f.mu.Lock()
	f.fail["incidents"] = true
	f.mu.Unlock()
	e2 := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	e2.analystLimitIncident(context.Background(), "x")
	if e2.m.incidentsCreated.Load() != 0 || e2.reg.OpenByRule(analystLimitRuleID) != nil {
		t.Fatal("при отказе хранилища инцидент не должен считаться созданным")
	}
	// Без реестра — тихий выход.
	(&engine{}).analystLimitIncident(context.Background(), "x")
}

func TestServeHTTPStopsOnContext(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.serveHTTP(ctx, addr); close(done) }()
	var resp *http.Response
	for i := 0; i < 100; i++ {
		var err error
		if resp, err = http.Get("http://" + addr + "/healthz"); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if resp == nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz через serveHTTP: %v", resp)
	}
	resp.Body.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP не остановился по отмене контекста")
	}
}
