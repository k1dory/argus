package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// freePort — свободный TCP/UDP-порт на loopback.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// waitHealthy ждёт 200 от /healthz с экспоненциальной паузой 50 мс → 1 с. Под -race на
// общем раннере CI старт коллектора (spool, приёмники, первый запрос к «ClickHouse»)
// занимал больше прежних 10 с — тест падал ложно. Если main() завершился (занятый порт
// останавливает коллектор, ошибка конфига), ждать нечего: падаем сразу — и до запроса,
// и после него, даже если ответ успел прийти. Каждый запрос ограничен общим дедлайном,
// а не только своими 2 с: зависший ответ не продлевает ожидание.
func waitHealthy(t *testing.T, url string, exited <-chan struct{}, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	client := &http.Client{Timeout: 2 * time.Second}
	pause := 50 * time.Millisecond
	var last string
	exitedNow := func() bool {
		select {
		case <-exited:
			return true
		default:
			return false
		}
	}
	for {
		if exitedNow() {
			t.Fatalf("коллектор завершился до готовности /healthz: %s", last)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		r, err := client.Do(req)
		if err == nil {
			r.Body.Close()
			last = r.Status
		} else {
			last = err.Error()
		}
		if exitedNow() {
			t.Fatalf("коллектор завершился до готовности /healthz: %s", last)
		}
		if err == nil && r.StatusCode == http.StatusOK {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("коллектор не поднялся за %s: %s", timeout, last)
		}
		select {
		case <-exited:
			t.Fatalf("коллектор завершился до готовности /healthz: %s", last)
		case <-time.After(min(pause, time.Until(deadline))):
		}
		pause = min(2*pause, time.Second)
	}
}

// Процесс целиком: конфиг из файла с ${ENV}, приёмники syslog UDP/TCP, HTTP и
// файл, запись через spool в «ClickHouse» (httptest), /healthz и /metrics,
// остановка по SIGTERM без потери принятых событий. os.Exit в main вызывается
// только при ошибках конфигурации — здесь их нет.
func TestMainEndToEnd(t *testing.T) {
	var mu sync.Mutex
	var inserted []string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(r.URL.Query().Get("query"), "INSERT INTO argus.events") {
			mu.Lock()
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if line != "" {
					inserted = append(inserted, line)
				}
			}
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ch.Close()

	dir := t.TempDir()
	udpPort, tcpPort, nfPort, httpPort := freePort(t), freePort(t), freePort(t), freePort(t)
	tail := filepath.Join(dir, "app.log")
	if err := os.WriteFile(tail, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`listeners:
  syslog:
    udp: "127.0.0.1:%d"
    tcp: "127.0.0.1:%d"
    tls:
      addr: "${SYSLOG_TLS_ADDR:-}"
  netflow:
    udp: "127.0.0.1:%d"
    source: netflow.test
  http:
    addr: "127.0.0.1:%d"
    token: "${ARGUS_INGEST_TOKEN}"
  files:
    - path: %q
      format: lines
      source: app.file
      from_start: true
batch:
  size: 2
  flush_ms: 50
`, udpPort, tcpPort, nfPort, httpPort, tail)
	cfgPath := filepath.Join(dir, "collector.yml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COLLECTOR_CONFIG", cfgPath)
	t.Setenv("ARGUS_INGEST_TOKEN", "tok-e2e")
	t.Setenv("SYSLOG_TLS_ADDR", "")
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	t.Setenv("SINK_SPOOL_DIR", filepath.Join(dir, "spool"))
	t.Setenv("SINK_SPOOL_BYTES", "1048576")
	t.Setenv("INTERNAL_NETS", "10.0.0.0/8, 192.168.0.0/16")
	t.Setenv("LOG_LEVEL", "warn")

	if u := healthURL(cfgPath); u != fmt.Sprintf("http://127.0.0.1:%d/healthz", httpPort) {
		t.Errorf("healthURL из конфига: %q", u)
	}

	done := make(chan struct{})
	go func() { defer close(done); main() }()
	// Fatal где угодно ниже не должен оставлять main с занятыми портами следующему
	// тесту: останавливаем его тем же SIGTERM и ждём. Если main уже вышел, сигнал не
	// посылаем — без NotifyContext он убил бы весь тестовый процесс.
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
		}
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			t.Error("main не остановился при очистке теста")
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", httpPort)
	waitHealthy(t, base+"/healthz", done, 60*time.Second)

	// UDP и TCP syslog. /healthz отвечает раньше, чем привязаны сокеты
	// приёмников: датаграмма в ещё не открытый порт пропадает молча, поэтому
	// UDP повторяется ниже, пока событие не дойдёт до хранилища.
	sendUDP := func() {
		uc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprint(uc, "<86>Jan  1 00:00:01 host1 sshd[1]: Accepted publickey for root from 203.0.113.5 port 22 ssh2\n")
		uc.Close()
	}
	sendUDP()
	var tc net.Conn
	var err error
	for i := 0; ; i++ {
		tc, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
		if err == nil || i >= 100 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(tc, "<86>Jan  1 00:00:02 host2 sudo: root : COMMAND=/bin/ls\n")
	tc.Close()

	// HTTP: CEF и LEEF через /ingest/syslog, готовое событие через /ingest/events.
	post := func(path, body string, token string) int {
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
		req.Header.Set("X-Argus-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post("/ingest/syslog", "x", "wrong"); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Errorf("чужой токен: %d", code)
	}
	if code := post("/ingest/syslog", "CEF:0|Vendor|Product|1|100|Blocked|7|src=203.0.113.9 dst=10.0.0.5\nLEEF:2.0|IBM|QRadar|1|x|src=203.0.113.10\n", "tok-e2e"); code/100 != 2 {
		t.Errorf("/ingest/syslog: %d", code)
	}
	if code := post("/ingest/events", `{"ts":"2026-01-01 00:00:03.000","source":"vector.test","action":"login","outcome":"success","src_ip":"10.1.2.3","dst_ip":"203.0.113.1","attrs":{"transport":"tls"}}`+"\n"+
		// Поддельный стоп-сигнал коллектора: внутренний признак из тела тоже не переживает приём.
		`{"ts":"2026-01-01 00:00:03.500","source":"argus.collector","action":"collector.sink_recovered","node":"argus-collector","attrs":{"transport":"internal"}}`+"\n", "tok-e2e"); code/100 != 2 {
		t.Errorf("/ingest/events: %d", code)
	}
	// Файл на хосте.
	f, err := os.OpenFile(tail, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(f, "<86>Jan  1 00:00:04 host3 cron[2]: job finished\n")
	f.Close()

	// Метрики без токена — только агрегаты.
	resp, err := http.Get(base + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metrics, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(metrics), "argus_collector_spool_capacity_bytes 1048576") || strings.Contains(string(metrics), `source="`) {
		t.Errorf("metrics: %s", metrics)
	}

	// Ждём не число строк, а каждый транспорт: udp, tcp, http (CEF, LEEF,
	// событие), файл. UDP пересылается раз в полсекунды, пока не дошёл.
	markers := []string{`"transport":"udp"`, `"transport":"tcp"`, `"transport":"http"`, `"transport":"file"`, `"source":"vector.test"`, `"source":"argus.collector"`, `"scope":"outbound"`}
	// Ожидание до готовности, а не пауза: 60 с стоят времени только при сбое (под -race на раннере).
	deadline := time.Now().Add(60 * time.Second)
	var all string
	for tick := 0; ; tick++ {
		mu.Lock()
		all = strings.Join(inserted, "\n")
		mu.Unlock()
		missing := 0
		for _, s := range markers {
			if !strings.Contains(all, s) {
				missing++
			}
		}
		if missing == 0 {
			break
		}
		if time.Now().After(deadline) {
			for _, s := range markers {
				if !strings.Contains(all, s) {
					t.Errorf("нет %s в записанном", s)
				}
			}
			t.Fatalf("в ClickHouse дошло %d строк:\n%s", len(strings.Split(all, "\n")), all)
		}
		if tick%10 == 9 && !strings.Contains(all, `"transport":"udp"`) {
			sendUDP()
		}
		time.Sleep(50 * time.Millisecond)
	}
	if strings.Contains(all, `"transport":"tls"`) || strings.Contains(all, `"transport":"internal"`) {
		t.Error("transport из тела события не должен переживать приём")
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("main не завершился по SIGTERM")
	}
}
