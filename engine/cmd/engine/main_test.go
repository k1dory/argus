package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// fakeCH — ClickHouse по HTTP: INSERT запоминает строки по таблицам,
// SELECT отвечает по подстроке запроса (иначе пусто).
type fakeCH struct {
	mu      sync.Mutex
	inserts map[string][]string
	selects map[string]string
	srv     *httptest.Server
}

func newFakeCH(t *testing.T) *fakeCH {
	t.Helper()
	f := &fakeCH{inserts: map[string][]string{}, selects: map[string]string{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 1<<20)
		n, _ := r.Body.Read(body)
		q := r.URL.Query().Get("query")
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasPrefix(q, "INSERT INTO ") {
			table := strings.Fields(q)[2]
			for _, line := range strings.Split(strings.TrimSpace(string(body[:n])), "\n") {
				if line != "" {
					f.inserts[table] = append(f.inserts[table], line)
				}
			}
			return
		}
		q = string(body[:n])
		for sub, resp := range f.selects {
			if strings.Contains(q, sub) {
				_, _ = w.Write([]byte(resp))
				return
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCH) rows(table string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.inserts[table]...)
}

func (f *fakeCH) waitRows(t *testing.T, table string, n int) []string {
	t.Helper()
	for i := 0; i < 200; i++ {
		if rows := f.rows(table); len(rows) >= n {
			return rows
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("в %s ожидалось %d строк, есть %v", table, n, f.rows(table))
	return nil
}

func rulesDirWith(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, yml := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(yml), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

const respondRule = `
title: WAF RCE
id: t-waf
level: critical
detection:
  selection: {source.class: waf, action: http.attack}
  condition: selection
dedupe: 30m
respond: {action: block_ip, target: src.ip, min_level: critical, ttl: 1h, min_events: 2}
`

func testEngine(t *testing.T, f *fakeCH, rulesDir string, rcfg respond.Config, token, mtoken string) *engine {
	t.Helper()
	rs, err := rules.Load(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	acfg, _ := analyst.LoadConfig("")
	acfg.Respond = rcfg
	ch := store.New(f.srv.URL, "argus", "default", "")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e := newEngine(ctx, rulesDir, rs, acfg, ch, token, mtoken)
	e.reg = incidents.NewRegistry(0, nil)
	return e
}

func ngfw(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var blocks int32
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/block" {
			mu.Lock()
			blocks++
			mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &blocks
}

func ipsConfig(srv *httptest.Server) respond.Config {
	return respond.Config{Mode: respond.ModeIPS, TrustedSources: []string{"10.0.10.0/24"},
		HTTP: []respond.HTTPAction{{Name: "ngfw.test", URL: srv.URL + "/block", Body: `{"ip":"${ip}"}`,
			Unblock: &respond.HTTPCall{URL: srv.URL + "/unblock", Body: `{"ip":"${ip}"}`}}}}
}

func do(t *testing.T, h http.Handler, method, path, token, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Argus-Token", token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestControlAPIRequiresToken(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "secret", "mtok")
	h := e.handler()
	if code, _ := do(t, h, "GET", "/healthz", "", ""); code != 200 {
		t.Fatalf("healthz без токена: %d", code)
	}
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/rules", ""}, {"GET", "/respond/status", ""}, {"POST", "/reload", ""},
		{"POST", "/respond/unblock", `{"ip":"203.0.113.9","user":"op","reason":"x"}`},
		{"POST", "/incidents/INC-1/respond", `{"action":"block_ip","ip":"203.0.113.9","reason":"x"}`},
		{"POST", "/incidents/INC-1/analyze", ""},
	} {
		if code, _ := do(t, h, c.method, c.path, "", c.body); code != 401 {
			t.Errorf("%s %s без токена: %d, ожидалось 401", c.method, c.path, code)
		}
		if code, _ := do(t, h, c.method, c.path, "wrong", c.body); code != 401 {
			t.Errorf("%s %s с чужим токеном: %d, ожидалось 401", c.method, c.path, code)
		}
	}
	if code, body := do(t, h, "GET", "/rules", "secret", ""); code != 200 || !strings.Contains(body, `"MinEvents":2`) {
		t.Fatalf("rules с токеном: %d %s", code, body)
	}
	if code, _ := do(t, h, "GET", "/metrics", "secret", ""); code != 401 {
		t.Fatalf("metrics должен принимать только METRICS_TOKEN: %d", code)
	}
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer mtok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "argus_engine_untrusted_skips_total") {
		t.Fatalf("metrics с Bearer METRICS_TOKEN: %d", rec.Code)
	}
	if code, _ := do(t, h, "POST", "/reload", "secret", ""); code != 202 {
		t.Fatalf("reload: %d", code)
	}
	if code, body := do(t, h, "GET", "/respond/status", "secret", ""); code != 200 || !strings.Contains(body, `"never_block"`) || !strings.Contains(body, `"manual_ttl"`) {
		t.Fatalf("respond/status: %d %s", code, body)
	}
	// ручная блокировка без причины — 400
	if code, _ := do(t, h, "POST", "/incidents/INC-1/respond", "secret", `{"action":"block_ip","ip":"203.0.113.9","user":"op"}`); code != 400 {
		t.Fatalf("блокировка без reason: %d", code)
	}
	// стенд: ARGUS_DEV без токена — открыто
	dev := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "", "")
	if code, _ := do(t, dev.handler(), "GET", "/rules", "", ""); code != 200 {
		t.Fatalf("без ENGINE_TOKEN (ARGUS_DEV) ручки открыты: %d", code)
	}
}

func TestUnblockEndpoint(t *testing.T) {
	f := newFakeCH(t)
	srv, _ := ngfw(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), ipsConfig(srv), "s", "s")
	h := e.handler()
	if code, body := do(t, h, "POST", "/respond/unblock", "s", `{"ip":"203.0.113.9","user":"op","reason":"ложное"}`); code != 422 || !strings.Contains(body, `"error"`) {
		t.Fatalf("неизвестный блок: %d %s", code, body)
	}
	if code, _ := do(t, h, "POST", "/respond/unblock", "s", `{"ip":"203.0.113.9","user":"op"}`); code != 400 {
		t.Fatal("без reason — 400")
	}
	if code, body := do(t, h, "POST", "/incidents/INC-1/respond", "s", `{"action":"block_ip","ip":"203.0.113.9","user":"op","reason":"вручную"}`); code != 200 || !strings.Contains(body, `"ttl":"24h0m0s"`) {
		t.Fatalf("ручная блокировка: %d %s", code, body)
	}
	code, body := do(t, h, "POST", "/respond/unblock", "s", `{"ip":"203.0.113.9","user":"petrov","reason":"ложное"}`)
	if code != 200 || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("снятие: %d %s", code, body)
	}
	rows := f.waitRows(t, "response_log", 3)
	last := rows[len(rows)-1]
	if !strings.Contains(last, `"mode":"manual_unblock"`) || !strings.Contains(last, `"actor":"petrov"`) || !strings.Contains(last, `"reason":"ложное"`) {
		t.Fatalf("журнал снятия: %s", last)
	}
	if len(e.resp.Active()) != 0 {
		t.Fatal("после снятия активных блоков нет")
	}
}

func wafEvent(ts, ip, transport, peer string) *model.Event {
	e := &model.Event{TS: ts, Source: "waf.modsecurity", SourceClass: "waf", Action: "http.attack", SrcIP: ip, ActorName: ip, Node: "shop", Attrs: map[string]string{}}
	if transport != "" {
		e.Attrs["transport"] = transport
	}
	if peer != "" {
		e.Attrs["peer"] = peer
	}
	return e
}

func TestAutoRespondTrustAndMinEvents(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := ngfw(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), ipsConfig(srv), "s", "s")
	now := time.Now()
	mk := func(id, ip string, evs ...*model.Event) *incidents.Incident {
		return &incidents.Incident{IncidentID: id, RuleID: "t-waf", RuleTitle: "WAF RCE", Level: "critical", EventCount: uint32(len(evs)), Events: evs}
	}
	// 1 событие из 2 — ожидание, исполнитель не вызван
	inc := mk("INC-1", "203.0.113.9", wafEvent("2026-09-10 10:00:00.000", "203.0.113.9", "file", ""))
	e.autoRespond(context.Background(), []*incidents.Incident{inc}, now)
	rows := f.waitRows(t, "response_log", 1)
	if !strings.Contains(rows[0], "ожидание: доверенных событий 1 из 2") || *blocks != 0 {
		t.Fatalf("min_events: %v blocks=%d", rows, *blocks)
	}
	// повторный вызов в том же состоянии ничего не пишет
	e.autoRespond(context.Background(), []*incidents.Incident{inc}, now)
	time.Sleep(50 * time.Millisecond)
	if len(f.rows("response_log")) != 1 {
		t.Fatalf("повтор ожидания: %v", f.rows("response_log"))
	}
	// доверенные транспорты (file + tcp от пира из trusted_sources) — блокировка
	inc2 := mk("INC-2", "203.0.113.10", wafEvent("2026-09-10 10:01:00.000", "203.0.113.10", "file", ""),
		wafEvent("2026-09-10 10:01:05.000", "203.0.113.10", "tcp", "10.0.10.11:40000"))
	e.autoRespond(context.Background(), []*incidents.Incident{inc2}, now)
	rows = f.waitRows(t, "response_log", 2)
	if !strings.Contains(rows[1], `"executor":"ngfw.test"`) || !strings.Contains(rows[1], `"ok":1`) || *blocks != 1 {
		t.Fatalf("trusted block: %v blocks=%d", rows, *blocks)
	}
	// решение принято — дописанный инцидент исполнителя не дёргает
	inc2.Events = append(inc2.Events, wafEvent("2026-09-10 10:01:09.000", "203.0.113.10", "file", ""))
	inc2.EventCount = 3
	e.autoRespond(context.Background(), []*incidents.Incident{inc2}, now)
	time.Sleep(50 * time.Millisecond)
	if len(f.rows("response_log")) != 2 || *blocks != 1 {
		t.Fatalf("повтор решения: %v blocks=%d", f.rows("response_log"), *blocks)
	}
	if e.m.untrustedSkips.Load() != 0 || e.m.autoBlocks.Load() != 1 || e.m.blockFailures.Load() != 0 {
		t.Fatalf("metrics: untrusted=%d blocks=%d failures=%d", e.m.untrustedSkips.Load(), e.m.autoBlocks.Load(), e.m.blockFailures.Load())
	}
}

// Недоверенное событие не накладывает вето на цепочку: порог и адреса
// считаются по доверенному подмножеству. [udp-спуф, file, file] при
// min_events=2 — блок; [udp, udp] — ожидание, не done, и блок после
// двух доверенных событий; адрес из спуфленного события не блокируется.
func TestAutoRespondTrustedSubset(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := ngfw(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), ipsConfig(srv), "s", "s")
	now := time.Now()
	mk := func(id string, evs ...*model.Event) *incidents.Incident {
		return &incidents.Incident{IncidentID: id, RuleID: "t-waf", RuleTitle: "WAF RCE", Level: "critical", EventCount: uint32(len(evs)), Events: evs}
	}
	// [udp-спуф с чужим адресом, file, file] → блокируется адрес из доверенных, спуфленный — нет
	inc := mk("INC-1",
		wafEvent("2026-09-10 10:00:00.000", "198.51.100.1", "udp", "192.0.2.77:514"),
		wafEvent("2026-09-10 10:00:01.000", "203.0.113.9", "file", ""),
		wafEvent("2026-09-10 10:00:02.000", "203.0.113.9", "file", ""))
	e.autoRespond(context.Background(), []*incidents.Incident{inc}, now)
	rows := f.waitRows(t, "response_log", 2)
	if !strings.Contains(rows[0], "предупреждение: 1 недоверенных событий не учтены") || !strings.Contains(rows[0], "192.0.2.77") {
		t.Fatalf("предупреждение о недоверенных: %v", rows)
	}
	if !strings.Contains(rows[1], `"executor":"ngfw.test"`) || !strings.Contains(rows[1], `"ip":"203.0.113.9"`) || !strings.Contains(rows[1], `"ok":1`) || *blocks != 1 {
		t.Fatalf("блок по доверенным: %v blocks=%d", rows, *blocks)
	}
	if len(e.resp.Active()) != 1 || e.resp.Active()[0].IP != "203.0.113.9" || e.respStatus("INC-1") != "done" {
		t.Fatalf("active=%+v state=%s", e.resp.Active(), e.respStatus("INC-1"))
	}
	// [udp, udp] → ожидание с предупреждением, не done; метрика недоверия
	inc2 := mk("INC-2",
		wafEvent("2026-09-10 10:01:00.000", "203.0.113.10", "udp", "192.0.2.77:514"),
		wafEvent("2026-09-10 10:01:01.000", "203.0.113.10", "udp", "192.0.2.77:514"))
	e.autoRespond(context.Background(), []*incidents.Incident{inc2}, now)
	rows = f.waitRows(t, "response_log", 3)
	if !strings.Contains(rows[2], "ожидание: доверенных событий 0 из 2") || !strings.Contains(rows[2], "не учтено недоверенных: 2") || !strings.Contains(rows[2], `"ok":0`) {
		t.Fatalf("ожидание по недоверию: %v", rows)
	}
	if e.respStatus("INC-2") != "waiting" || *blocks != 1 || e.m.untrustedSkips.Load() != 1 {
		t.Fatalf("state=%s blocks=%d untrusted=%d", e.respStatus("INC-2"), *blocks, e.m.untrustedSkips.Load())
	}
	// дотянули доверенными: одно file-событие — всё ещё мало (1 из 2), второе — блок
	inc2.Events = append(inc2.Events, wafEvent("2026-09-10 10:01:05.000", "203.0.113.10", "file", ""))
	inc2.EventCount = 3
	e.autoRespond(context.Background(), []*incidents.Incident{inc2}, now)
	time.Sleep(50 * time.Millisecond)
	if e.respStatus("INC-2") != "waiting" || *blocks != 1 {
		t.Fatalf("1 доверенное из 2: state=%s blocks=%d", e.respStatus("INC-2"), *blocks)
	}
	inc2.Events = append(inc2.Events, wafEvent("2026-09-10 10:01:06.000", "203.0.113.10", "file", ""))
	inc2.EventCount = 4
	e.autoRespond(context.Background(), []*incidents.Incident{inc2}, now)
	rows = f.waitRows(t, "response_log", 5)
	if e.respStatus("INC-2") != "done" || *blocks != 2 || !strings.Contains(rows[4], `"ip":"203.0.113.10"`) || !strings.Contains(rows[4], `"ok":1`) {
		t.Fatalf("блок после доверенных: state=%s blocks=%d rows=%v", e.respStatus("INC-2"), *blocks, rows)
	}
	// «уже заблокирован» другим инцидентом — не отказ: blockFailures не растёт
	inc3 := mk("INC-3",
		wafEvent("2026-09-10 10:02:00.000", "203.0.113.10", "file", ""),
		wafEvent("2026-09-10 10:02:01.000", "203.0.113.10", "file", ""))
	e.autoRespond(context.Background(), []*incidents.Incident{inc3}, now)
	rows = f.waitRows(t, "response_log", 6)
	if !strings.Contains(rows[5], "уже заблокирован") || e.m.blockFailures.Load() != 0 || *blocks != 2 {
		t.Fatalf("уже заблокирован: %v failures=%d", rows[5], e.m.blockFailures.Load())
	}
}

// Снимок для autoRespond: параллельный Apply следующего цикла перезаписывает
// Events/EventCount того же инцидента — с -race гонки быть не должно.
func TestAutoRespondSnapshotRace(t *testing.T) {
	f := newFakeCH(t)
	srv, _ := ngfw(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), ipsConfig(srv), "s", "s")
	now := time.Now()
	buf := []*model.Event{
		wafEvent("2026-09-10 10:00:00.000", "203.0.113.1", "file", ""),
		wafEvent("2026-09-10 10:00:01.000", "203.0.113.1", "file", ""),
	}
	e.cycle(context.Background(), e.current(), buf) // go autoRespond(snapshot)
	// следующий цикл сразу дописывает тот же инцидент
	for i := 0; i < 20; i++ {
		buf = append(buf, wafEvent("2026-09-10 10:00:0"+string(rune('2'+i%7))+".000", "203.0.113.1", "file", ""))
		dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: buf, Now: now})
		e.reg.Apply(dets, now.Add(time.Duration(i+1)*time.Second))
	}
	f.waitRows(t, "response_log", 1)
	// снимок независим от оригинала
	inc := &incidents.Incident{IncidentID: "INC-9", Events: []*model.Event{buf[0]}, EventCount: 1}
	snap := snapshotIncidents([]*incidents.Incident{inc})
	inc.Events = append(inc.Events, buf[1])
	inc.EventCount = 2
	if len(snap[0].Events) != 1 || snap[0].EventCount != 1 || snap[0] == inc {
		t.Fatalf("snapshot: %+v", snap[0])
	}
}

// После рестарта открытые инциденты с правилом respond считаются решёнными;
// чистка respState по возрасту; Prune не трогает инциденты absence-правил.
func TestRespStateRestoreAndPrune(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule, "a.yml": absenceRule}), respond.Config{}, "s", "s")
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	open := []incidents.Incident{
		{IncidentID: "INC-1", RuleID: "t-waf", Status: incidents.StatusNew},
		{IncidentID: "INC-2", RuleID: "t-absence", Status: incidents.StatusNew},
		{IncidentID: "INC-3", RuleID: "unknown", Status: incidents.StatusNew},
	}
	if n := e.restoreRespState(open, now); n != 1 || e.respStatus("INC-1") != "done" || e.respStatus("INC-2") != "" {
		t.Fatalf("restore: n=%d INC-1=%s INC-2=%s", n, e.respStatus("INC-1"), e.respStatus("INC-2"))
	}
	e.setRespStatus("INC-4", "waiting", now.Add(-72*time.Hour))
	if n := e.pruneRespState(now, respStateTTL); n != 1 || e.respStatus("INC-4") != "" || e.respStatus("INC-1") != "done" {
		t.Fatalf("prune: n=%d", n)
	}
	// раз в respPruneCycles циклов чистка запускается из cycle
	e.setRespStatus("INC-5", "done", now.Add(-72*time.Hour))
	e.respCycles = respPruneCycles - 1
	e.cycle(context.Background(), e.current(), nil)
	if e.respStatus("INC-5") != "" || e.respCycles != 0 {
		t.Fatalf("чистка из cycle: state=%q cycles=%d", e.respStatus("INC-5"), e.respCycles)
	}
	// Prune реестра: закрытый инцидент absence-правила остаётся якорем
	reg := incidents.NewRegistry(3, []incidents.Incident{
		{IncidentID: "INC-1", RuleID: "t-waf", Status: incidents.StatusClosed, ActorName: "x", UpdatedAt: "2026-09-01 10:00:00"},
		{IncidentID: "INC-2", RuleID: "t-absence", Status: incidents.StatusClosed, ActorName: "y", UpdatedAt: "2026-09-01 10:00:00"},
	})
	keep := func(id string) bool { r := e.ruleFor(id); return r != nil && r.IsAbsence() }
	if n := reg.Prune(now, 24*time.Hour, keep); n != 1 || reg.OpenByRule("t-absence") != nil {
		t.Fatalf("prune absence: n=%d", n)
	}
	if reg.Prune(now, 24*time.Hour, nil) != 1 {
		t.Fatal("без предиката чистится и absence")
	}
}

const absenceRule = `
title: Backup silent
id: t-absence
level: high
detection:
  selection: {source.class: backup}
  threshold: {kind: absence, window: 1h, group_by: node}
  condition: selection | threshold
`

func TestWazuhPlaceholderPassword(t *testing.T) {
	if wazuhPlaceholderPassword(nil, "", "change-me") != "" || wazuhPlaceholderPassword(nil, "https://m:55000", "real") != "" {
		t.Fatal("без URL или с настоящим паролем — не ошибка")
	}
	if wazuhPlaceholderPassword(nil, "https://m:55000", "change-me") == "" || wazuhPlaceholderPassword(nil, "https://m:55000", " change-me-2 ") == "" {
		t.Fatal("URL задан, пароль-заглушка — отказ")
	}
	if wazuhPlaceholderPassword(&respond.WazuhAR{APIURL: "https://m:55000", Password: "change-me"}, "", "") == "" {
		t.Fatal("заглушка в конфиге исполнителя — отказ")
	}
	if wazuhPlaceholderPassword(&respond.WazuhAR{APIURL: "", Password: "change-me"}, "", "") != "" {
		t.Fatal("исполнитель без api_url — не ошибка")
	}
}

func TestExceptionFieldsEndpoint(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	if code, _ := do(t, e.handler(), "GET", "/rules/exception_fields", "", ""); code != 401 {
		t.Fatalf("без токена: %d", code)
	}
	code, body := do(t, e.handler(), "GET", "/rules/exception_fields", "s", "")
	var out struct {
		Fields []string `json:"exception_fields"`
	}
	if err := json.Unmarshal([]byte(body), &out); code != 200 || err != nil || strings.Join(out.Fields, ",") != strings.Join(eval.ExceptionFields(), ",") || !strings.Contains(body, "dst.ip") {
		t.Fatalf("%d %s", code, body)
	}
}

func TestSchedulerCooldownAndDailyLimit(t *testing.T) {
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	s := newScheduler(1, 2, 5*time.Minute)
	s.nowFn = func() time.Time { return now }
	if ok, _, _ := s.admit("INC-1", true); !ok {
		t.Fatal("первый разбор проходит")
	}
	if ok, why, _ := s.admit("INC-1", true); ok || !strings.Contains(why, "cooldown") {
		t.Fatalf("повтор в cooldown: %v %s", ok, why)
	}
	if ok, _, _ := s.admit("INC-2", true); !ok {
		t.Fatal("второй облачный проходит (лимит 2)")
	}
	ok, why, hit := s.admit("INC-3", true)
	if ok || !hit || !strings.Contains(why, "лимит") {
		t.Fatalf("третий облачный — лимит с системным инцидентом: %v %v %s", ok, hit, why)
	}
	if ok, _, hit := s.admit("INC-4", true); ok || hit {
		t.Fatal("после лимита инцидент заводится один раз")
	}
	if ok, _, _ := s.admit("INC-5", false); !ok {
		t.Fatal("локальный профиль лимитом не ограничен")
	}
	now = now.Add(6 * time.Minute)
	if ok, _, _ := s.admit("INC-1", false); !ok {
		t.Fatal("после cooldown разбор снова разрешён")
	}
	now = now.Add(24 * time.Hour)
	if ok, _, _ := s.admit("INC-6", true); !ok {
		t.Fatal("новые сутки — счётчик обнулён")
	}
}

func TestScheduleAnalyzeQueueAndWritesVerdict(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	e.sched = newScheduler(1, 500, 5*time.Minute) // воркеры ещё не запущены — очередь копится
	inc := &incidents.Incident{IncidentID: "INC-1", RuleID: "t-waf", RuleTitle: "WAF RCE", Level: "critical", Chain: []string{"x"}, FirstTS: "2026-09-10 10:00:00", EventCount: 1}
	if ok, _ := e.scheduleAnalyze(inc, e.ruleFor("t-waf")); !ok {
		t.Fatal("разбор должен встать в очередь")
	}
	time.Sleep(100 * time.Millisecond)
	if len(f.rows("incident_verdicts")) != 0 || len(e.sched.queue) != 1 {
		t.Fatal("без воркеров разбор не должен идти")
	}
	e.startAnalystWorkers()
	rows := f.waitRows(t, "incident_verdicts", 1)
	var v store.Verdict
	if err := json.Unmarshal([]byte(rows[0]), &v); err != nil || v.IncidentID != "INC-1" || v.Shown != 1 || !strings.HasPrefix(v.ShownReason, "показан") {
		t.Fatalf("verdict: %s %v", rows[0], err)
	}
	if ok, why := e.scheduleAnalyze(inc, nil); ok || !strings.Contains(why, "cooldown") {
		t.Fatalf("повторный разбор в cooldown: %v %s", ok, why)
	}
	if code, body := do(t, e.handler(), "POST", "/incidents/INC-1/analyze", "s", ""); code != 404 || !strings.Contains(body, "не найден") {
		t.Fatalf("analyze несуществующего: %d %s", code, body)
	}
}

// Переполнение очереди разборов: отказ с метрикой, HTTP 429, cooldown и
// суточный счётчик откатываются; после запуска воркеров очередь разбирается.
func TestScheduleAnalyzeQueueFull(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	e.sched = newScheduler(1, 500, 5*time.Minute)
	capacity := 1 * analystQueueFactor
	if cap(e.sched.queue) != capacity {
		t.Fatalf("ёмкость %d, ожидалось concurrency×%d", cap(e.sched.queue), analystQueueFactor)
	}
	mk := func(i int) *incidents.Incident {
		return &incidents.Incident{IncidentID: "INC-" + strconv.Itoa(i), RuleID: "t-waf", RuleTitle: "WAF RCE", Level: "critical", Chain: []string{"x"}, EventCount: 1}
	}
	for i := 1; i <= capacity; i++ {
		if ok, why := e.scheduleAnalyze(mk(i), e.ruleFor("t-waf")); !ok {
			t.Fatalf("задача %d: %s", i, why)
		}
	}
	if ok, why := e.scheduleAnalyze(mk(capacity+1), nil); ok || why != errQueueFull || e.m.analystRejected.Load() != 1 {
		t.Fatalf("переполнение: ok=%v why=%q rejected=%d", ok, why, e.m.analystRejected.Load())
	}
	// отказ не оставляет cooldown: тот же инцидент можно поставить снова, когда место появится
	e.sched.mu.Lock()
	_, cooled := e.sched.last["INC-"+strconv.Itoa(capacity+1)]
	e.sched.mu.Unlock()
	if cooled {
		t.Fatal("отклонённая задача не должна попадать в cooldown")
	}
	f.selects["FROM incidents_current WHERE incident_id ="] = `{"incident_id":"INC-99","status":"new","rule_id":"t-waf","rule_title":"WAF RCE","level":"critical","event_count":1,"updated_at":"2026-09-14 10:00:00"}` + "\n"
	code, body := do(t, e.handler(), "POST", "/incidents/INC-99/analyze", "s", "")
	if code != 429 || !strings.Contains(body, `"error":"`+errQueueFull+`"`) {
		t.Fatalf("HTTP при переполнении: %d %s", code, body)
	}
	e.startAnalystWorkers()
	f.waitRows(t, "incident_verdicts", capacity)
	if code, _ := do(t, e.handler(), "POST", "/incidents/INC-99/analyze", "s", ""); code != 202 {
		t.Fatalf("после разгрузки очереди разбор принимается: %d", code)
	}
}

func TestCycleStormAndPrune(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	e.reg.SetMaxNew(1)
	buf := []*model.Event{
		wafEvent("2026-09-10 10:00:00.000", "203.0.113.1", "file", ""),
		wafEvent("2026-09-10 10:00:01.000", "203.0.113.2", "file", ""),
		wafEvent("2026-09-10 10:00:02.000", "203.0.113.3", "file", ""),
	}
	e.cycle(context.Background(), e.current(), buf)
	rows := f.rows("incidents")
	if len(rows) != 2 {
		t.Fatalf("1 инцидент + 1 шторм, есть %d: %v", len(rows), rows)
	}
	var storm incidents.Incident
	_ = json.Unmarshal([]byte(rows[1]), &storm)
	if storm.RuleID != stormRuleID || storm.ActorName != "t-waf" || !strings.Contains(storm.Chain[0], "отброшено 2") {
		t.Fatalf("шторм: %+v", storm)
	}
	if e.m.incidentsDropped.Load() != 2 || e.m.incidentsCreated.Load() != 2 {
		t.Fatalf("metrics: dropped=%d created=%d", e.m.incidentsDropped.Load(), e.m.incidentsCreated.Load())
	}
	// второй цикл: освободилось место — ещё один инцидент, шторм дописан, а не заведён заново
	e.cycle(context.Background(), e.current(), buf)
	rows = f.rows("incidents")
	if len(rows) != 4 {
		t.Fatalf("повторный цикл: %d строк: %v", len(rows), rows)
	}
	_ = json.Unmarshal([]byte(rows[3]), &storm)
	if storm.RuleID != stormRuleID || storm.EventCount != 2 || len(storm.Chain) != 2 {
		t.Fatalf("шторм должен дописываться: %+v", storm)
	}
	// Prune: финальные инциденты старше 24h уходят из реестра
	reg := incidents.NewRegistry(3, []incidents.Incident{
		{IncidentID: "INC-1", RuleID: "a", Status: incidents.StatusClosed, ActorName: "x", UpdatedAt: "2026-09-01 10:00:00"},
		{IncidentID: "INC-2", RuleID: "a", Status: incidents.StatusNew, ActorName: "y", UpdatedAt: "2026-09-01 10:00:00"},
		{IncidentID: "INC-3", RuleID: "a", Status: incidents.StatusFalsePositive, ActorName: "z", UpdatedAt: "2026-09-13 10:00:00"},
	})
	if n := reg.Prune(time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC), 24*time.Hour, nil); n != 1 {
		t.Fatalf("prune: %d", n)
	}
}

func TestWriteIncidentsPreservesJournalState(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	f.selects[`FROM incidents_current WHERE incident_id IN`] = `{"incident_id":"INC-1","status":"in_progress","owner":"ivanov","note":"смотрю","updated_max":"2026-09-14 10:00:01"}` + "\n"
	now := time.Date(2026, 9, 14, 10, 0, 0, 0, time.UTC)
	inc := &incidents.Incident{IncidentID: "INC-1", RuleID: "t-waf", Status: incidents.StatusNew, EventCount: 3, UpdatedAt: "2026-09-14 10:00:00", CreatedAt: "2026-09-14 09:00:00", FirstTS: "2026-09-14 09:00:00", LastTS: "2026-09-14 10:00:00"}
	e.writeIncidents(context.Background(), []*incidents.Incident{inc}, nil, now)
	rows := f.rows("incidents")
	if len(rows) != 1 {
		t.Fatalf("ожидалась одна запись снимка: %v", rows)
	}
	var written incidents.Incident
	_ = json.Unmarshal([]byte(rows[0]), &written)
	if written.Status != incidents.StatusInProgress || written.Owner != "ivanov" || written.Note != "смотрю" {
		t.Fatalf("снимок должен учитывать состояние из журнала: %+v", written)
	}
}
