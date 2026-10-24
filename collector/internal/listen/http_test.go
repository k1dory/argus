package listen

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

func newTestHandlers(token string) (*HTTPHandlers, *[]model.Event, *[]Peer) {
	var events []model.Event
	var peers []Peer
	h := &HTTPHandlers{
		Token: token,
		Emit:  func(e model.Event) { events = append(events, e) },
		Lines: func(line string, p Peer) { peers = append(peers, p) },
		Health: func() any {
			return map[string]any{"status": "ok"}
		},
		Metrics: func(full bool) string {
			if full {
				return "argus_collector_events_total 1\nargus_collector_source_events_total{source=\"ngfw.x\"} 1\n"
			}
			return "argus_collector_events_total 1\n"
		},
	}
	return h, &events, &peers
}

func TestHTTPAcceptsOnlyAfterDurableBatch(t *testing.T) {
	h, _, _ := newTestHandlers("")
	var saved []model.Event
	h.EmitBatch = func(_ context.Context, events []model.Event) error { saved = append(saved, events...); return nil }
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()
	good := `{"source":"one"}` + "\n" + `{"source":"two"}`
	if code, _ := do(t, srv, "POST", "/ingest/events", "", good+"\n{"); code != 400 || len(saved) != 0 {
		t.Fatalf("ошибка в конце батча не должна принять начало: %d, saved=%d", code, len(saved))
	}
	h.EmitBatch = func(context.Context, []model.Event) error { return errors.New("disk full") }
	if code, _ := do(t, srv, "POST", "/ingest/events", "", good); code != 503 {
		t.Fatalf("ошибка дисковой очереди: %d, want 503", code)
	}
	h.EmitBatch = func(_ context.Context, events []model.Event) error { saved = append(saved, events...); return nil }
	if code, _ := do(t, srv, "POST", "/ingest/events", "", good); code != 202 || len(saved) != 2 {
		t.Fatalf("батч после записи на диск: %d, saved=%d", code, len(saved))
	}
}

func TestHTTPRejectsOversizedBatchWithoutAcknowledgingPrefix(t *testing.T) {
	h, _, _ := newTestHandlers("")
	called := false
	h.EmitBatch = func(context.Context, []model.Event) error { called = true; return nil }
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()
	before := Metrics.Oversize.Load()
	code, _ := do(t, srv, "POST", "/ingest/harbor", "", `{"type":"push"}`+strings.Repeat(" ", 4<<20))
	if code != http.StatusRequestEntityTooLarge || called {
		t.Fatalf("крупный запрос: status=%d, emit=%v", code, called)
	}
	if Metrics.Oversize.Load() != before+1 {
		t.Fatal("превышение лимита не посчитано")
	}
}

func do(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Argus-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestTokenAndMetricsVisibility(t *testing.T) {
	h, _, peers := newTestHandlers("secret-token")
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()

	if code, _ := do(t, srv, "POST", "/ingest/syslog", "", "<34>1 - h a - - - x"); code != 401 {
		t.Errorf("без токена: %d", code)
	}
	if code, _ := do(t, srv, "POST", "/ingest/syslog", "secret-toke", "x"); code != 401 {
		t.Errorf("токен-префикс: %d", code)
	}
	if code, _ := do(t, srv, "POST", "/ingest/syslog", "secret-token", "<34>1 - h a - - - x\n"); code != 202 {
		t.Errorf("верный токен: %d", code)
	}
	if len(*peers) != 1 || (*peers)[0].Transport != "http" || (*peers)[0].Addr != "127.0.0.1" {
		t.Errorf("peer: %+v", *peers)
	}
	code, body := do(t, srv, "GET", "/metrics", "", "")
	if code != 200 || strings.Contains(body, "source_events_total") {
		t.Errorf("/metrics без токена не должен раскрывать источники: %d %q", code, body)
	}
	code, body = do(t, srv, "GET", "/metrics", "secret-token", "")
	if code != 200 || !strings.Contains(body, "source_events_total") {
		t.Errorf("/metrics с токеном — полная версия: %d %q", code, body)
	}
	if code, _ := do(t, srv, "GET", "/healthz", "", ""); code != 200 {
		t.Errorf("/healthz без токена: %d", code)
	}
}

func TestIngestEventsEnsuresAndRecovers(t *testing.T) {
	h, events, _ := newTestHandlers("")
	h.WAFAudit = func(json.RawMessage) bool { panic("boom") }
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()

	code, _ := do(t, srv, "POST", "/ingest/events", "", `{"ts":"2999-01-01 00:00:00.000","source":"x","attrs":{"transport":"tls"}}`)
	if code != 202 || len(*events) != 1 {
		t.Fatalf("events: %d %v", code, *events)
	}
	e := (*events)[0]
	if e.Attrs["ts_raw"] != "2999-01-01 00:00:00.000" {
		t.Errorf("ts вне окна должен уйти в ts_raw: %v", e.Attrs)
	}
	before := Metrics.Panics.Load()
	code, _ = do(t, srv, "POST", "/ingest/modsecurity", "", `{"transaction":{}}`)
	if code != 500 {
		t.Errorf("паника в хендлере → 500, got %d", code)
	}
	if Metrics.Panics.Load() != before+1 {
		t.Error("паника не посчитана")
	}
	// сервер жив после паники
	if code, _ := do(t, srv, "GET", "/healthz", "", ""); code != 200 {
		t.Errorf("после паники /healthz: %d", code)
	}
}

// /ingest/syslog: батч со строкой длиннее 1 МБ отвергается целиком (413) —
// ни одна строка до неё не эмитится, иначе повтор клиента даст дубли.
func TestIngestSyslogTwoPass(t *testing.T) {
	h, _, peers := newTestHandlers("")
	srv := httptest.NewServer(h.Mux())
	defer srv.Close()
	before := Metrics.Oversize.Load()
	body := "<34>1 - h a - - - one\n<34>1 - h a - - - two\n" + strings.Repeat("x", 2<<20) + "\n"
	code, _ := do(t, srv, "POST", "/ingest/syslog", "", body)
	if code != 413 {
		t.Fatalf("status %d, want 413", code)
	}
	if len(*peers) != 0 {
		t.Errorf("строки до длинной эмитились: %d", len(*peers))
	}
	if Metrics.Oversize.Load() != before+1 {
		t.Error("oversize не посчитан")
	}
	code, resp := do(t, srv, "POST", "/ingest/syslog", "", "<34>1 - h a - - - one\n\n<34>1 - h a - - - two\n")
	if code != 202 || !strings.Contains(resp, `"accepted":2`) || len(*peers) != 2 {
		t.Errorf("обычный батч: %d %q peers=%d", code, resp, len(*peers))
	}
}
