package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/store"
)

const repoRulesDir = "../../../rules"

func TestReadNDJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ev.ndjson")
	body := "# комментарий\n\n" +
		`{"ts":"2026-09-10 10:00:00.000","source":"ssh","action":"login.fail","actor_name":"root"}` + "\n" +
		"   \n" +
		`{"source":"waf","action":"http.attack","src_ip":"203.0.113.1","attrs":{"k":"v"}}` + "\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	events, err := readNDJSON(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("событий %d, ожидалось 2 (комментарии и пустые строки пропускаются)", len(events))
	}
	// Ensure: outcome/actor_kind по умолчанию, attrs не nil, ts проставлен.
	if events[0].Outcome != "unknown" || events[0].ActorKind != "unknown" || events[0].Attrs == nil {
		t.Fatalf("Ensure не применён: %+v", events[0])
	}
	if events[1].TS == "" || events[1].Attrs["k"] != "v" {
		t.Fatalf("второе событие: %+v", events[1])
	}

	bad := filepath.Join(dir, "bad.ndjson")
	_ = os.WriteFile(bad, []byte("{\"source\":\"x\"}\nне json\n"), 0o600)
	if _, err := readNDJSON(bad); err == nil || !strings.Contains(err.Error(), "bad.ndjson") {
		t.Fatalf("битая строка должна давать ошибку с путём: %v", err)
	}
	if _, err := readNDJSON(filepath.Join(dir, "нет.ndjson")); err == nil {
		t.Fatal("отсутствующий файл — ошибка")
	}
}

func TestRulesTestRepoSuite(t *testing.T) {
	if _, err := os.Stat(filepath.Join(repoRulesDir, "tests")); err != nil {
		t.Skip("каталог rules/tests недоступен:", err)
	}
	if code := rulesTest(repoRulesDir, []string{"--dir", repoRulesDir}); code != 0 {
		t.Fatalf("rules test по правилам репозитория: код %d", code)
	}
}

func TestRulesTestReplayAndEdgeCases(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(filepath.Join(rulesDir, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(rulesDir, "r.yml"), []byte(respondRule), 0o600)
	// Без тестов — 0 и сообщение «нет тестов».
	empty := filepath.Join(dir, "empty")
	_ = os.MkdirAll(empty, 0o755)
	_ = os.WriteFile(filepath.Join(empty, "r.yml"), []byte(respondRule), 0o600)
	if code := rulesTest(empty, nil); code != 0 {
		t.Fatalf("каталог без tests/: код %d", code)
	}

	// Replay: две сработки WAF по одному адресу.
	fixture := filepath.Join(dir, "fixtures", "waf.ndjson")
	_ = os.MkdirAll(filepath.Dir(fixture), 0o755)
	_ = os.WriteFile(fixture, []byte(
		`{"ts":"2026-09-10 10:00:00.000","source":"waf","source_class":"waf","action":"http.attack","src_ip":"203.0.113.1","actor_name":"203.0.113.1"}`+"\n"+
			`{"ts":"2026-09-10 10:00:01.000","source":"waf","source_class":"waf","action":"http.attack","src_ip":"203.0.113.1","actor_name":"203.0.113.1"}`+"\n"), 0o600)
	if code := rulesTest(rulesDir, []string{"--replay", fixture}); code != 0 {
		t.Fatalf("replay: код %d", code)
	}
	if code := rulesTest(rulesDir, []string{"--replay", filepath.Join(dir, "нет.ndjson")}); code != 1 {
		t.Fatalf("replay без файла: код %d, ожидался 1", code)
	}

	// Тесты: удачный, с неверным ожиданием, с неизвестным правилом, битый YAML, без фикстуры.
	write := func(name, body string) { _ = os.WriteFile(filepath.Join(rulesDir, "tests", name), []byte(body), 0o600) }
	write("ok.yml", "rule: t-waf\nfixture: fixtures/waf.ndjson\nexpect_incidents: 1\nexpect_actor: 203.0.113.1\nmin_events: 2\nexpect_respond_min_events: 2\n")
	if code := rulesTest(rulesDir, nil); code != 0 {
		t.Fatalf("удачный тест: код %d", code)
	}
	write("wrong.yml", "rule: t-waf\nfixture: fixtures/waf.ndjson\nexpect_incidents: 3\nexpect_actor: 198.51.100.1\nmin_events: 9\nexpect_respond_min_events: 1\n")
	write("norule.yml", "rule: нет-такого\nfixture: fixtures/waf.ndjson\nexpect_incidents: 1\n")
	write("broken.yml", "rule: [\n")
	write("nofixture.yml", "rule: t-waf\nfixture: fixtures/нет.ndjson\nexpect_incidents: 1\n")
	write("offset.yml", "rule: t-waf\nfixture: fixtures/waf.ndjson\nexpect_incidents: 1\nnow_offset: 20m\n")
	if code := rulesTest(rulesDir, nil); code != 1 {
		t.Fatalf("провальные тесты должны давать код 1, got %d", code)
	}
}

func TestWaitReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitReport(ctx, time.Hour) {
		t.Fatal("отменённый контекст — false")
	}
	if !waitReport(context.Background(), time.Millisecond) {
		t.Fatal("истёкший таймер — true")
	}
}

func TestFormatRiskReport(t *testing.T) {
	now := time.Date(2026, 10, 29, 9, 30, 0, 0, time.UTC)
	r := store.RiskReport{
		Totals: store.RiskTotals{Open: 4, Unassigned: 2, Overdue: 1, Critical: 1},
		Owners: []store.RiskOwner{{Owner: "", Open: 2, Overdue: 1}, {Owner: "anna", Open: 2}},
		Top: []store.RiskIncident{
			{ID: "INC-7", Title: "WAF RCE", Level: "critical", Status: "new", Owner: "", Deadline: "2026-10-29 09:00:00", Overdue: 1},
			{ID: "INC-8", Title: "SSH", Level: "high", Status: "in_progress", Owner: "anna", Deadline: "2026-10-29 10:30:00"},
		},
	}
	got := formatRiskReport(r, now)
	for _, want := range []string{
		"ARGUS — риски на 2026-10-29 09:30 UTC",
		"Открытых: 4; критичных: 1; без ответственного: 2; просрочена реакция: 1.",
		"- не назначен: открытых 2, просрочено 1",
		"- anna: открытых 2, просрочено 0",
		"- INC-7 [critical] WAF RCE; new; ответственный: не назначен; реакция до 2026-10-29 09:00:00 UTC ПРОСРОЧЕНО",
		"- INC-8 [high] SSH; in_progress; ответственный: anna; реакция до 2026-10-29 10:30:00 UTC\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("в отчёте нет %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "ПРОСРОЧЕНО") != 1 {
		t.Fatal("метка просрочки только у просроченного")
	}
}

func TestRunRiskReportsRetriesOnErrors(t *testing.T) {
	// Ошибка чтения срока → повтор через 5 минут; ошибка отчёта → повтор; ошибка SMTP → повтор.
	var waits []time.Duration
	wait := func(_ context.Context, d time.Duration) bool { waits = append(waits, d); return len(waits) < 3 }

	ch := &flakyStore{stub: &reportStoreStub{}, lastErr: errors.New("ch down")}
	mail := &reportSenderStub{}
	runRiskReports(context.Background(), ch, mail, time.Hour, wait)
	if len(waits) != 3 || waits[0] != 5*time.Minute || mail.calls != 0 {
		t.Fatalf("ожидались три повтора по 5 минут без писем: %v, писем %d", waits, mail.calls)
	}

	waits = nil
	ch = &flakyStore{stub: &reportStoreStub{}, reportErr: errors.New("query failed")}
	runRiskReports(context.Background(), ch, mail, time.Hour, wait)
	if len(waits) != 3 || waits[0] != 5*time.Minute || mail.calls != 0 {
		t.Fatalf("ошибка отчёта: %v, писем %d", waits, mail.calls)
	}

	waits = nil
	ch = &flakyStore{stub: &reportStoreStub{}}
	bad := &failingReportSender{err: errors.New("smtp 451")}
	runRiskReports(context.Background(), ch, bad, time.Hour, wait)
	if len(waits) != 3 || waits[0] != 5*time.Minute || bad.calls != 3 || len(ch.stub.receipts) != 0 {
		t.Fatalf("ошибка SMTP: %v, попыток %d, квитанций %d", waits, bad.calls, len(ch.stub.receipts))
	}
}

type flakyStore struct {
	stub               *reportStoreStub
	lastErr, reportErr error
}

func (s *flakyStore) RiskReportLastSent(ctx context.Context) (time.Time, error) {
	if s.lastErr != nil {
		return time.Time{}, s.lastErr
	}
	return s.stub.RiskReportLastSent(ctx)
}
func (s *flakyStore) RiskReport(ctx context.Context) (store.RiskReport, error) {
	if s.reportErr != nil {
		return store.RiskReport{}, s.reportErr
	}
	return s.stub.RiskReport(ctx)
}
func (s *flakyStore) RecordRiskReportDelivery(ctx context.Context, at time.Time) error {
	return s.stub.RecordRiskReportDelivery(ctx, at)
}

type failingReportSender struct {
	err   error
	calls int
}

func (s *failingReportSender) Send(context.Context, string, string) error { s.calls++; return s.err }

func TestIsWorkflowUserError(t *testing.T) {
	if !isWorkflowUserError(workflowUserError("x")) || !isWorkflowUserError(errors.Join(errors.New("w"), workflowUserError("y"))) {
		t.Fatal("ошибка пользователя распознаётся и в обёртке")
	}
	if isWorkflowUserError(errIncidentMissing) || isWorkflowUserError(nil) {
		t.Fatal("прочие ошибки — не пользовательские")
	}
	if workflowUserError("текст").Error() != "текст" {
		t.Fatal("Error()")
	}
}

func TestSyncRespondMode(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{Mode: "simulate"}, "s", "s")
	ctx := context.Background()

	f.mu.Lock()
	f.selects["FROM console_settings"] = `{"value":"ids"}` + "\n"
	f.mu.Unlock()
	e.syncRespondMode(ctx)
	if mode, from := e.resp.Mode(); mode != respond.ModeIDS || from != "console" {
		t.Fatalf("режим из консоли: %s/%s", mode, from)
	}

	// Неизвестное значение — предупреждение, режим прежний.
	f.mu.Lock()
	f.selects["FROM console_settings"] = `{"value":"bogus"}` + "\n"
	f.mu.Unlock()
	e.syncRespondMode(ctx)
	if mode, _ := e.resp.Mode(); mode != respond.ModeIDS {
		t.Fatalf("неизвестное значение не должно менять режим: %s", mode)
	}

	// Пусто — обратно к конфигу.
	f.mu.Lock()
	f.selects["FROM console_settings"] = `{"value":""}` + "\n"
	f.mu.Unlock()
	e.syncRespondMode(ctx)
	if mode, from := e.resp.Mode(); mode != respond.ModeSimulate || from != "config" {
		t.Fatalf("пустое значение возвращает конфиг: %s/%s", mode, from)
	}

	// Хранилище недоступно — тихо, режим прежний.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", 503) }))
	defer dead.Close()
	e.ch = store.New(dead.URL, "argus", "", "")
	e.syncRespondMode(ctx)
	if mode, _ := e.resp.Mode(); mode != respond.ModeSimulate {
		t.Fatal("ошибка хранилища не меняет режим")
	}
}

func TestLogResponses(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	ctx := context.Background()
	e.logResponses(ctx, nil)
	if len(f.rows("response_log")) != 0 {
		t.Fatal("пустой список не пишется")
	}
	e.logResponses(ctx, []store.ResponseRow{{TS: "2026-10-29 10:00:00", IncidentID: "INC-1", IP: "203.0.113.1", Mode: "manual", Executor: "ngfw", OK: 1, Actor: "anna"}})
	rows := f.waitRows(t, "response_log", 1)
	if !strings.Contains(rows[0], `"incident_id":"INC-1"`) || !strings.Contains(rows[0], `"actor":"anna"`) {
		t.Fatalf("строка журнала: %s", rows[0])
	}
	f.mu.Lock()
	f.fail["response_log"] = true
	f.mu.Unlock()
	e.logResponses(ctx, []store.ResponseRow{{IncidentID: "INC-2"}}) // ошибка только в лог
}

func TestExpireBlocksWritesResponseLog(t *testing.T) {
	var unblocks atomic.Int32
	ngfw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/unblock" {
			unblocks.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ngfw.Close()
	f := newFakeCH(t)
	rcfg := respond.Config{Mode: respond.ModeIPS, TTL: "1h",
		HTTP: []respond.HTTPAction{{Name: "ngfw.test", URL: ngfw.URL + "/block", Body: `{"ip":"${ip}"}`, Unblock: &respond.HTTPCall{URL: ngfw.URL + "/unblock", Body: `{"ip":"${ip}"}`}}}}
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), rcfg, "s", "s")
	ctx := context.Background()

	// Ничего не истекло — записей нет.
	e.expireBlocks(ctx, time.Now())
	if len(f.rows("response_log")) != 0 {
		t.Fatal("без истёкших блокировок журнал не пишется")
	}

	results, applied, err := e.resp.Auto(ctx, "203.0.113.9", "INC-1", "тест", 20*time.Millisecond)
	if err != nil || !applied {
		t.Fatalf("автоблокировка: %v applied=%v %+v", err, applied, results)
	}
	time.Sleep(40 * time.Millisecond)
	e.expireBlocks(ctx, time.Now())
	rows := f.waitRows(t, "response_log", 1)
	if !strings.Contains(rows[0], `"reason":"TTL истёк"`) || !strings.Contains(rows[0], `"ip":"203.0.113.9"`) ||
		!strings.Contains(rows[0], `"mode":"ips"`) || !strings.Contains(rows[0], `"actor":"argus-engine"`) {
		t.Fatalf("запись о снятии: %s", rows[0])
	}
	if unblocks.Load() != 1 {
		t.Fatalf("снятий у исполнителя %d, ожидалось 1", unblocks.Load())
	}
	if len(e.resp.Active()) != 0 {
		t.Fatal("блокировка должна исчезнуть из активных")
	}
}
