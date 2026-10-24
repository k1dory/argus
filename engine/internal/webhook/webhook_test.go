package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

type memStore struct {
	mu      sync.Mutex
	recs    map[string]Record
	failGet atomic.Int32 // сколько следующих Lookup вернут ошибку
}

func newMemStore() *memStore { return &memStore{recs: map[string]Record{}} }

func (s *memStore) LookupWebhookDelivery(_ context.Context, target, key string) (Record, bool, error) {
	if s.failGet.Load() > 0 {
		s.failGet.Add(-1)
		return Record{}, false, errors.New("clickhouse недоступен")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[target+"|"+key]
	return r, ok, nil
}

func (s *memStore) SaveWebhookDelivery(_ context.Context, r Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs[r.Target+"|"+r.Key] = r
	return nil
}

func (s *memStore) get(target, key string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[target+"|"+key]
	return r, ok
}

// fakeHook — приёмник JSON POST: считает доставки, умеет отвечать ошибками.
type fakeHook struct {
	hits   atomic.Int32
	fail   atomic.Int32 // столько следующих запросов ответят 503
	status int          // если не 0 — всегда этот код
	mu     sync.Mutex
	byEv   map[string]Payload // последняя доставка по типу события
	auth   string
}

func (f *fakeHook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var p Payload
	_ = json.NewDecoder(r.Body).Decode(&p)
	f.mu.Lock()
	f.auth = r.Header.Get("Authorization")
	f.mu.Unlock()
	if f.status != 0 {
		w.WriteHeader(f.status)
		return
	}
	if f.fail.Load() > 0 {
		f.fail.Add(-1)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	f.hits.Add(1)
	f.mu.Lock()
	if f.byEv == nil {
		f.byEv = map[string]Payload{}
	}
	f.byEv[p.Event] = p
	f.mu.Unlock()
}

const testSecret = "0123456789abcdef0123456789abcdef"

func hookRoute(srv *httptest.Server) *Route {
	return &Route{Name: "soc", MinLevel: "high", Target: &HTTPTarget{Name: "soc", URL: srv.URL, Secret: testSecret, Token: "bearer-x", HTTP: srv.Client()}}
}

func fastOpts() Options {
	return Options{Workers: 4, MaxAttempts: 4, BaseBackoff: 5 * time.Millisecond, MaxBackoff: 20 * time.Millisecond, Timeout: 2 * time.Second, ConsoleURL: "https://argus.example/"}
}

func incident(id, level string) *incidents.Incident {
	return &incidents.Incident{IncidentID: id, Level: level, Status: incidents.StatusNew, RuleID: "ssh-bruteforce",
		RuleTitle: "Перебор SSH", ActorName: "203.0.113.7", Node: "web-01", Sources: []string{"linux.auth"},
		EventCount: 42, FirstTS: "2026-10-12 10:00:00.000", LastTS: "2026-10-12 10:05:00.000",
		Chain: []string{"10:00:00  linux.auth  web-01  ssh.login.failure  root"}}
}

func start(t *testing.T, d *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	t.Cleanup(func() { cancel(); d.Wait() })
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("не дождались: %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// settle — очередь пуста и отложенных ретраев нет: дальше ничего не произойдёт.
func settle(t *testing.T, d *Dispatcher, m *TargetMetrics, total int64) {
	t.Helper()
	eventually(t, "все события обработаны", func() bool {
		return m.Delivered.Load()+m.Failed.Load()+m.Deduped.Load() >= total
	})
}

func TestDeliveryPayloadAndDedup(t *testing.T) {
	hook := &fakeHook{}
	srv := httptest.NewServer(hook)
	defer srv.Close()
	store := newMemStore()
	d := New([]*Route{hookRoute(srv)}, store, fastOpts())
	start(t, d)

	inc := incident("INC-7", "critical")
	d.Notify(EventCreated, inc)
	d.Notify(EventCreated, inc) // повтор того же события
	esc := *inc
	esc.Status = incidents.StatusEscalated
	d.Notify(EventEscalated, &esc) // эскалация — другое событие, доставляется
	m := d.Metrics("soc")
	settle(t, d, m, 3)

	if got := hook.hits.Load(); got != 2 {
		t.Fatalf("доставок %d, ожидалось 2 (created и escalated)", got)
	}
	if m.Delivered.Load() != 2 || m.Deduped.Load() != 1 {
		t.Fatalf("delivered=%d deduped=%d", m.Delivered.Load(), m.Deduped.Load())
	}
	rec, ok := store.get("soc", "INC-7|"+EventCreated)
	if !ok || rec.State != StateDelivered || rec.Ref != "200" {
		t.Fatalf("отметка %+v ok=%v", rec, ok)
	}
	hook.mu.Lock()
	defer hook.mu.Unlock()
	if hook.auth != "Bearer bearer-x" {
		t.Fatalf("Authorization %q", hook.auth)
	}
	p := hook.byEv[EventEscalated]
	if p.Event != EventEscalated || p.Incident.ID != "INC-7" || p.Incident.Level != "critical" || p.Incident.Status != incidents.StatusEscalated {
		t.Fatalf("тело %+v", p)
	}
	if c := hook.byEv[EventCreated]; c.Incident.Status != incidents.StatusNew || c.DeliveryID == p.DeliveryID {
		t.Fatalf("created: %+v", c)
	}
	if p.Incident.URL != "https://argus.example/incidents/INC-7" || p.SentAt == "" || p.DeliveryID == "" {
		t.Fatalf("ссылка/метки %+v", p)
	}
	if len(p.Incident.Chain) != 0 {
		t.Fatal("цепочка событий ушла без include_chain")
	}
}

func TestDedupSurvivesRestart(t *testing.T) {
	hook := &fakeHook{}
	srv := httptest.NewServer(hook)
	defer srv.Close()
	store := newMemStore()

	d1 := New([]*Route{hookRoute(srv)}, store, fastOpts())
	start(t, d1)
	d1.Notify(EventCreated, incident("INC-8", "high"))
	settle(t, d1, d1.Metrics("soc"), 1)

	// «Перезапуск»: новый диспетчер с пустым кешем, та же база.
	d2 := New([]*Route{hookRoute(srv)}, store, fastOpts())
	start(t, d2)
	d2.Notify(EventCreated, incident("INC-8", "high"))
	settle(t, d2, d2.Metrics("soc"), 1)

	if got := hook.hits.Load(); got != 1 {
		t.Fatalf("после перезапуска доставок %d, ожидалась 1", got)
	}
	if d2.Metrics("soc").Deduped.Load() != 1 {
		t.Fatal("повтор после перезапуска не посчитан как дедуп")
	}
}

func TestConcurrentSameEventDeliveredOnce(t *testing.T) {
	hook := &fakeHook{}
	srv := httptest.NewServer(hook)
	defer srv.Close()
	d := New([]*Route{hookRoute(srv)}, newMemStore(), fastOpts())
	start(t, d)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Notify(EventCreated, incident("INC-9", "critical"))
		}()
	}
	wg.Wait()
	settle(t, d, d.Metrics("soc"), 20)
	if got := hook.hits.Load(); got != 1 {
		t.Fatalf("параллельные одинаковые события доставлены %d раз", got)
	}
}

func TestRetryWithBackoffThenDelivered(t *testing.T) {
	hook := &fakeHook{}
	hook.fail.Store(2)
	srv := httptest.NewServer(hook)
	defer srv.Close()
	d := New([]*Route{hookRoute(srv)}, newMemStore(), fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-10", "high"))
	m := d.Metrics("soc")
	settle(t, d, m, 1)
	if m.Delivered.Load() != 1 || m.Retries.Load() != 2 || hook.hits.Load() != 1 {
		t.Fatalf("delivered=%d retries=%d hits=%d", m.Delivered.Load(), m.Retries.Load(), hook.hits.Load())
	}
}

// stepTarget — цель из двух шагов: первый создаёт объект и сохраняет его id
// через checkpoint, второй может упасть. Ретрай после сбоя второго шага не
// должен повторять первый.
type stepTarget struct {
	creates, finishes atomic.Int32
	failFinish        atomic.Int32
}

func (s *stepTarget) DedupKey(p Payload) string { return p.Incident.ID }

func (s *stepTarget) Deliver(_ context.Context, _ Payload, rec Record, checkpoint func(string) error) (string, error) {
	ref := rec.Ref
	if rec.State != StateCreated || ref == "" {
		ref = fmt.Sprintf("obj-%d", s.creates.Add(1))
		_ = checkpoint(ref)
	}
	if s.failFinish.Load() > 0 {
		s.failFinish.Add(-1)
		return ref, errors.New("второй шаг не удался")
	}
	s.finishes.Add(1)
	return ref, nil
}

func TestCheckpointSurvivesRetry(t *testing.T) {
	st := &stepTarget{}
	st.failFinish.Store(2)
	store := newMemStore()
	d := New([]*Route{{Name: "steps", MinLevel: "high", Target: st}}, store, fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-11", "critical"))
	m := d.Metrics("steps")
	settle(t, d, m, 1)
	if st.creates.Load() != 1 || st.finishes.Load() != 1 || m.Retries.Load() != 2 || m.Delivered.Load() != 1 {
		t.Fatalf("creates=%d finishes=%d retries=%d delivered=%d", st.creates.Load(), st.finishes.Load(), m.Retries.Load(), m.Delivered.Load())
	}
	if rec, ok := store.get("steps", "INC-11"); !ok || rec.State != StateDelivered || rec.Ref != "obj-1" {
		t.Fatalf("отметка %+v ok=%v", rec, ok)
	}
}

func TestRetriesExhausted(t *testing.T) {
	hook := &fakeHook{}
	hook.fail.Store(100)
	srv := httptest.NewServer(hook)
	defer srv.Close()
	d := New([]*Route{hookRoute(srv)}, newMemStore(), fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-12", "high"))
	m := d.Metrics("soc")
	settle(t, d, m, 1)
	if m.Failed.Load() != 1 || m.Retries.Load() != 3 || m.Delivered.Load() != 0 {
		t.Fatalf("failed=%d retries=%d delivered=%d (MaxAttempts=4)", m.Failed.Load(), m.Retries.Load(), m.Delivered.Load())
	}
}

func TestPermanentErrorNotRetried(t *testing.T) {
	hook := &fakeHook{status: http.StatusForbidden}
	srv := httptest.NewServer(hook)
	defer srv.Close()
	d := New([]*Route{hookRoute(srv)}, newMemStore(), fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-13", "critical"))
	m := d.Metrics("soc")
	settle(t, d, m, 1)
	if m.Failed.Load() != 1 || m.Retries.Load() != 0 {
		t.Fatalf("403: failed=%d retries=%d", m.Failed.Load(), m.Retries.Load())
	}
}

func TestStoreErrorRetriesInsteadOfDuplicating(t *testing.T) {
	hook := &fakeHook{}
	srv := httptest.NewServer(hook)
	defer srv.Close()
	store := newMemStore()
	store.failGet.Store(2)
	d := New([]*Route{hookRoute(srv)}, store, fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-14", "high"))
	m := d.Metrics("soc")
	settle(t, d, m, 1)
	if hook.hits.Load() != 1 || m.Retries.Load() != 2 {
		t.Fatalf("hits=%d retries=%d", hook.hits.Load(), m.Retries.Load())
	}
}

func TestLevelAndEventFilter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	escOnly := &Route{Name: "esc-only", MinLevel: "high", Events: []string{EventEscalated},
		Target: &HTTPTarget{Name: "esc-only", URL: srv.URL, Secret: testSecret, HTTP: srv.Client()}}
	all := &Route{Name: "all", MinLevel: "high",
		Target: &HTTPTarget{Name: "all", URL: srv.URL, Secret: testSecret, HTTP: srv.Client()}}
	d := New([]*Route{escOnly, all}, newMemStore(), fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-15", "critical")) // esc-only: не тот тип; all: доставка
	d.Notify(EventCreated, incident("INC-16", "medium"))   // ниже порога — никуда
	d.Notify(EventEscalated, incident("INC-17", "low"))    // ручная эскалация — обеим целям, порог не действует
	settle(t, d, d.Metrics("esc-only"), 1)
	settle(t, d, d.Metrics("all"), 2)
	time.Sleep(20 * time.Millisecond)
	if hits.Load() != 3 {
		t.Fatalf("доставок %d, ожидалось 3", hits.Load())
	}
	if d.Metrics("esc-only").Delivered.Load() != 1 || d.Metrics("all").Delivered.Load() != 2 {
		t.Fatalf("esc-only=%d all=%d", d.Metrics("esc-only").Delivered.Load(), d.Metrics("all").Delivered.Load())
	}
}

func TestStatusErrorQuotesBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, "bad\nlevel=ERROR msg=\"подделка\"\x1b[31m")
	}))
	defer srv.Close()
	_, err := (&HTTPTarget{Name: "soc", URL: srv.URL, HTTP: srv.Client()}).Deliver(context.Background(), Payload{}, Record{}, nil)
	if err == nil || strings.ContainsAny(err.Error(), "\n\x1b") || !IsPermanent(err) {
		t.Fatalf("ошибка %q", err)
	}
}

func TestHTTPTargetSignatureAndDedupPerEvent(t *testing.T) {
	var mu sync.Mutex
	var got []*http.Request
	var bodies [][]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r)
		bodies = append(bodies, b)
		mu.Unlock()
	}))
	defer srv.Close()
	r := &Route{Name: "soc", MinLevel: "high", IncludeChain: true,
		Target: &HTTPTarget{Name: "soc", URL: srv.URL, Secret: testSecret, Token: "bearer-x", HTTP: srv.Client()}}
	store := newMemStore()
	d := New([]*Route{r}, store, fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-18", "critical"))
	settle(t, d, d.Metrics("soc"), 1)
	d.Notify(EventCreated, incident("INC-18", "critical"))
	d.Notify(EventEscalated, incident("INC-18", "critical"))
	settle(t, d, d.Metrics("soc"), 3)

	if rec, ok := store.get("soc", "INC-18|"+EventCreated); !ok || rec.Ref != "200" {
		t.Fatalf("у HTTP-цели ref — код ответа: %+v", rec)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("доставок %d, ожидалось 2 (created и escalated, повтор created — дедуп)", len(got))
	}
	for i, req := range got {
		if sig := req.Header.Get("X-Argus-Signature"); sig != Sign(testSecret, bodies[i]) {
			t.Fatalf("подпись %q не сходится", sig)
		}
		if req.Header.Get("Authorization") != "Bearer bearer-x" || req.Header.Get("X-Argus-Delivery") == "" {
			t.Fatalf("заголовки %v", req.Header)
		}
		var p Payload
		if err := json.Unmarshal(bodies[i], &p); err != nil {
			t.Fatal(err)
		}
		if p.Incident.ID != "INC-18" || len(p.Incident.Chain) != 1 || p.Event != req.Header.Get("X-Argus-Event") || p.SentAt == "" {
			t.Fatalf("тело %+v", p)
		}
	}
	if got[0].Header.Get("X-Argus-Delivery") == got[1].Header.Get("X-Argus-Delivery") {
		t.Fatal("у разных событий одинаковый delivery id")
	}
}

func TestHTTPTargetRedirectIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	}))
	defer srv.Close()
	r := &Route{Name: "soc", MinLevel: "high", Target: &HTTPTarget{Name: "soc", URL: srv.URL, Secret: testSecret, HTTP: newHTTPClient()}}
	d := New([]*Route{r}, newMemStore(), fastOpts())
	start(t, d)
	d.Notify(EventCreated, incident("INC-19", "high"))
	m := d.Metrics("soc")
	settle(t, d, m, 1)
	if m.Failed.Load() != 1 || m.Retries.Load() != 0 {
		t.Fatalf("редирект: failed=%d retries=%d", m.Failed.Load(), m.Retries.Load())
	}
}

func TestQueueOverflowDrops(t *testing.T) {
	r := &Route{Name: "soc", MinLevel: "low", Target: &HTTPTarget{Name: "soc", URL: "https://127.0.0.1:1", HTTP: newHTTPClient()}}
	opts := fastOpts()
	opts.QueueSize = 2
	d := New([]*Route{r}, newMemStore(), opts) // воркеры не запущены — очередь не разбирается
	for i := 0; i < 5; i++ {
		d.Notify(EventCreated, incident(fmt.Sprintf("INC-%d", 30+i), "high"))
	}
	if got := d.Metrics("soc").Dropped.Load(); got != 3 {
		t.Fatalf("отброшено %d, ожидалось 3", got)
	}
	var b strings.Builder
	d.WriteMetrics(&b)
	for _, want := range []string{`argus_engine_webhook_deliveries_total{target="soc",result="dropped"} 3`, "argus_engine_webhook_queue 2"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("в метриках нет %q:\n%s", want, b.String())
		}
	}
}

func TestBuildConfig(t *testing.T) {
	env := map[string]string{
		"HOOK_URL":    "https://soc.example/hook",
		"HOOK_SECRET": strings.Repeat("z", 32),
		"HOOK_TOKEN":  "bearer-token",
		"PLAIN_URL":   "http://soc.example/hook",
		"SHORT":       "short",
	}
	getenv := func(k string) string { return env[k] }

	routes, problems := Build([]TargetConfig{
		{Name: "soc", Kind: "webhook", URLEnv: "HOOK_URL", SecretEnv: "HOOK_SECRET", TokenEnv: "HOOK_TOKEN", MinLevel: "critical"},
		{Name: "default-kind", URLEnv: "HOOK_URL", SecretEnv: "HOOK_SECRET"},
		{Name: "off", Kind: "webhook", URLEnv: "UNSET_URL", SecretEnv: "HOOK_SECRET"}, // адрес не задан — выключена молча
	}, getenv)
	if len(problems) != 0 || len(routes) != 2 {
		t.Fatalf("routes=%d problems=%v", len(routes), problems)
	}
	if routes[0].MinLevel != "critical" || routes[1].MinLevel != "high" {
		t.Fatalf("пороги %q %q", routes[0].MinLevel, routes[1].MinLevel)
	}
	if ht := routes[0].Target.(*HTTPTarget); ht.Token != "bearer-token" || ht.Secret != env["HOOK_SECRET"] {
		t.Fatalf("цель %+v", ht)
	}

	bad := []TargetConfig{
		{Name: "Bad Name", URLEnv: "HOOK_URL"},
		{Name: "plain", URLEnv: "PLAIN_URL", SecretEnv: "HOOK_SECRET"},
		{Name: "value-not-name", URLEnv: "https://soc.example/hook"},
		{Name: "short", URLEnv: "HOOK_URL", SecretEnv: "SHORT"},
		{Name: "nosecret", URLEnv: "HOOK_URL"},
		{Name: "lvl", URLEnv: "HOOK_URL", SecretEnv: "HOOK_SECRET", MinLevel: "urgent"},
		{Name: "ev", URLEnv: "HOOK_URL", SecretEnv: "HOOK_SECRET", Events: []string{"incident.closed"}},
		{Name: "kind", Kind: "slack", URLEnv: "HOOK_URL"},
		{Name: "kind2", Kind: "tracker", URLEnv: "HOOK_URL", SecretEnv: "HOOK_SECRET"},
	}
	routes, problems = Build(bad, getenv)
	if len(routes) != 0 || len(problems) != len(bad) {
		t.Fatalf("routes=%d problems=%d: %v", len(routes), len(problems), problems)
	}
	for _, p := range problems {
		for _, secret := range []string{env["HOOK_SECRET"], env["HOOK_TOKEN"], "short\""} {
			if strings.Contains(p, secret) {
				t.Fatalf("значение секрета в сообщении: %s", p)
			}
		}
	}
	plain := TargetConfig{Name: "plain", URLEnv: "PLAIN_URL", SecretEnv: "HOOK_SECRET", AllowHTTP: true}
	if routes, problems := Build([]TargetConfig{plain}, getenv); len(routes) != 1 || len(problems) != 0 {
		t.Fatalf("allow_http: routes=%d problems=%v", len(routes), problems)
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	d := New([]*Route{{Name: "x", Target: &HTTPTarget{}}}, nil, Options{BaseBackoff: time.Second, MaxBackoff: 10 * time.Second})
	for attempt, want := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 10 * time.Second, 10 * time.Second} {
		got := d.backoff(attempt + 0)
		if got < want*8/10 || got > want*12/10 {
			t.Fatalf("attempt %d: %v, ожидалось %v ±20%%", attempt, got, want)
		}
	}
	if got := d.backoff(64); got > 12*time.Second || got <= 0 {
		t.Fatalf("переполнение сдвига: %v", got)
	}
}

func TestWaitTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	r := &Route{Name: "slow", MinLevel: "high", Target: &HTTPTarget{Name: "slow", URL: srv.URL, Secret: testSecret, HTTP: srv.Client()}}
	d := New([]*Route{r}, newMemStore(), fastOpts())
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	d.Notify(EventCreated, incident("INC-50", "high"))
	if d.WaitTimeout(30 * time.Millisecond) {
		t.Fatal("без остановки воркеры не должны завершиться")
	}
	cancel() // отмена прерывает зависший запрос и отложенные ретраи
	if !d.WaitTimeout(2 * time.Second) {
		t.Fatal("после отмены диспетчер не остановился")
	}
	var nilD *Dispatcher
	if !nilD.WaitTimeout(time.Millisecond) {
		t.Fatal("nil-диспетчер должен считаться остановленным")
	}
}

// Pending — что бросается при остановке: очередь и ретраи в паузе.
func TestPendingCountsQueueAndRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	r := &Route{Name: "down", MinLevel: "high", Target: &HTTPTarget{Name: "down", URL: srv.URL, HTTP: srv.Client()}}
	opts := fastOpts()
	opts.BaseBackoff, opts.MaxBackoff = time.Hour, time.Hour
	d := New([]*Route{r}, newMemStore(), opts)
	d.Notify(EventCreated, incident("INC-60", "high"))
	d.Notify(EventCreated, incident("INC-61", "high"))
	if q, rt := d.Pending(); q != 2 || rt != 0 {
		t.Fatalf("до запуска: queued=%d retries=%d", q, rt)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if q, rt := d.Pending(); q == 0 && rt == 2 {
			break
		}
		if time.Now().After(deadline) {
			q, rt := d.Pending()
			t.Fatalf("после первой попытки: queued=%d retries=%d", q, rt)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if !d.WaitTimeout(2 * time.Second) {
		t.Fatal("после отмены диспетчер не остановился")
	}
	if q, rt := d.Pending(); q != 0 || rt != 0 {
		t.Fatalf("после остановки: queued=%d retries=%d", q, rt)
	}
	if d.Metrics("down").Dropped.Load() != 2 {
		t.Fatalf("брошенные ретраи считаются в dropped: %d", d.Metrics("down").Dropped.Load())
	}
	var nilD *Dispatcher
	if q, rt := nilD.Pending(); q+rt != 0 {
		t.Fatal("nil-диспетчер")
	}
}
