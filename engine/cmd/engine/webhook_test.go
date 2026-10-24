package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/webhook"
)

type hookSink struct {
	mu       sync.Mutex
	payloads []webhook.Payload
}

func (s *hookSink) got() []webhook.Payload {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]webhook.Payload{}, s.payloads...)
}

func (s *hookSink) wait(t *testing.T, n int) []webhook.Payload {
	t.Helper()
	for i := 0; i < 300; i++ {
		if p := s.got(); len(p) >= n {
			return p
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("вебхуков ожидалось %d, пришло %d", n, len(s.got()))
	return nil
}

// hookEngine — движок с одной HTTP-целью вебхука (min_level high).
func hookEngine(t *testing.T, f *fakeCH, rulesDir string) (*engine, *hookSink) {
	t.Helper()
	sink := &hookSink{}
	secret := strings.Repeat("h", 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Argus-Signature") != webhook.Sign(secret, body) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var p webhook.Payload
		_ = json.Unmarshal(body, &p)
		sink.mu.Lock()
		sink.payloads = append(sink.payloads, p)
		sink.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	t.Setenv("TEST_HOOK_URL", srv.URL)
	t.Setenv("TEST_HOOK_SECRET", secret)

	rs, err := rules.Load(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	acfg, _ := analyst.LoadConfig("")
	acfg.Notify.Webhooks = []webhook.TargetConfig{{Name: "soc", Kind: "webhook", MinLevel: "high",
		URLEnv: "TEST_HOOK_URL", SecretEnv: "TEST_HOOK_SECRET", AllowHTTP: true}}
	ctx, cancel := context.WithCancel(context.Background())
	e := newEngine(ctx, rulesDir, rs, acfg, store.New(f.srv.URL, "argus", "default", ""), "s", "s")
	if e.hooks == nil {
		t.Fatal("цель вебхука не включилась")
	}
	e.reg = incidents.NewRegistry(0, nil)
	e.hooks.Start(ctx)
	t.Cleanup(func() { cancel(); e.hooks.Wait() })
	return e, sink
}

func TestCycleSendsWebhookForNewIncident(t *testing.T) {
	f := newFakeCH(t)
	e, sink := hookEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}))
	buf := []*model.Event{
		wafEvent("2026-09-10 10:00:00.000", "203.0.113.1", "file", ""),
		wafEvent("2026-09-10 10:00:01.000", "203.0.113.1", "file", ""),
	}
	e.cycle(context.Background(), e.current(), buf)
	p := sink.wait(t, 1)[0]
	if p.Event != webhook.EventCreated || p.Incident.ID != "INC-1" || p.Incident.Level != "critical" || p.Incident.Status != incidents.StatusEscalated {
		t.Fatalf("вебхук %+v", p)
	}
	rows := f.waitRows(t, "webhook_deliveries", 1)
	if !strings.Contains(rows[0], `"state":"delivered"`) || !strings.Contains(rows[0], `"dedup_key":"INC-1|incident.created"`) {
		t.Fatalf("отметка доставки %v", rows)
	}
}

func TestWorkflowEscalationSendsWebhook(t *testing.T) {
	f := newFakeCH(t)
	f.selects["FROM incidents_current WHERE incident_id ="] = `{"incident_id":"INC-5","status":"in_progress","owner":"anna","rule_id":"t-waf","rule_title":"WAF RCE","level":"high","event_count":3}` + "\n"
	f.selects["max(revision)"] = `{"revision":"2"}` + "\n"
	e, sink := hookEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}))
	if _, err := e.transitionIncident(context.Background(), "INC-5", workflowRequest{Actor: "anna", Role: "analyst", Kind: "status", Status: incidents.StatusEscalated}); err != nil {
		t.Fatal(err)
	}
	p := sink.wait(t, 1)[0]
	if p.Event != webhook.EventEscalated || p.Incident.ID != "INC-5" || p.Incident.Status != incidents.StatusEscalated {
		t.Fatalf("вебхук эскалации %+v", p)
	}
	// Перевод в другой статус вебхук не шлёт.
	if _, err := e.transitionIncident(context.Background(), "INC-5", workflowRequest{Actor: "anna", Role: "analyst", Kind: "status", Status: incidents.StatusObserving}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if n := len(sink.got()); n != 1 {
		t.Fatalf("вебхуков %d, ожидался 1", n)
	}
}

func TestWebhookMetricsExposed(t *testing.T) {
	f := newFakeCH(t)
	e, _ := hookEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}))
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s")
	rec := httptest.NewRecorder()
	e.handler().ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `argus_engine_webhook_deliveries_total{target="soc",result="delivered"} 0`) {
		t.Fatalf("метрик вебхуков нет:\n%s", rec.Body.String())
	}
}

// Пример конфига из репозитория грузится, а цели без адресов в окружении молча выключены.
func TestRepoAnalystConfigWebhooks(t *testing.T) {
	acfg, err := analyst.LoadConfig("../../argus.analyst.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(acfg.Notify.Webhooks) != 1 || acfg.Notify.Webhooks[0].Kind != "webhook" {
		t.Fatalf("целей в примере %d: %+v", len(acfg.Notify.Webhooks), acfg.Notify.Webhooks)
	}
	routes, problems := webhook.Build(acfg.Notify.Webhooks, func(string) string { return "" })
	if len(routes) != 0 || len(problems) != 0 {
		t.Fatalf("без окружения: routes=%d problems=%v", len(routes), problems)
	}
	env := map[string]string{"ARGUS_WEBHOOK_URL": "https://soc.example/hook", "ARGUS_WEBHOOK_SECRET": "short"}
	if _, problems := webhook.Build(acfg.Notify.Webhooks, func(k string) string { return env[k] }); len(problems) != 1 || !strings.Contains(problems[0], "secret_env") {
		t.Fatalf("короткий секрет должен выключить цель с причиной: %v", problems)
	}
	env["ARGUS_WEBHOOK_SECRET"] = strings.Repeat("s", 32)
	if routes, problems := webhook.Build(acfg.Notify.Webhooks, func(k string) string { return env[k] }); len(routes) != 1 || len(problems) != 0 {
		t.Fatalf("с адресом и секретом цель включена: routes=%d problems=%v", len(routes), problems)
	}
	for name, p := range acfg.Profiles {
		if p.Backend != "openai-compatible" && p.Backend != "mock" {
			t.Fatalf("профиль %s: бэкенд %q", name, p.Backend)
		}
	}
}
