package pull

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// s3Mock — минимальный S3: ListObjectsV2 (prefix, start-after) и GetObject по
// ключу. Проверяет, что каждый запрос подписан SigV4.
type s3Mock struct {
	srv       *httptest.Server
	bucket    string
	mu        sync.Mutex
	objects   map[string]string // ключ → тело; пустое тело — объект нулевого размера
	lists     []string          // start-after каждого листинга
	prefixes  []string
	gets      []string
	listCode  atomic.Int32 // ≠0 — отдать этот статус на листинг
	listCalls atomic.Int32 // все листинги, включая отказанные
	getFail   map[string]int
	onGet     func(key string)
	badSigned atomic.Int32
}

func newS3Mock(t *testing.T, objects map[string]string) *s3Mock {
	m := &s3Mock{bucket: "audit", objects: objects, getFail: map[string]int{}}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AK/") || r.Header.Get("x-amz-date") == "" || r.Header.Get("x-amz-content-sha256") == "" {
			m.badSigned.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/"+m.bucket) {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("list-type") == "2" {
			m.listCalls.Add(1)
			if c := m.listCode.Load(); c != 0 {
				w.WriteHeader(int(c))
				_, _ = w.Write([]byte(`<Error><Code>InternalError</Code></Error>`))
				return
			}
			after, prefix := r.URL.Query().Get("start-after"), r.URL.Query().Get("prefix")
			m.mu.Lock()
			m.lists = append(m.lists, after)
			m.prefixes = append(m.prefixes, prefix)
			keys := make([]string, 0, len(m.objects))
			for k := range m.objects {
				if strings.HasPrefix(k, prefix) && k > after {
					keys = append(keys, k)
				}
			}
			m.mu.Unlock()
			sort.Strings(keys)
			type c struct {
				Key          string `xml:"Key"`
				LastModified string `xml:"LastModified"`
				Size         int64  `xml:"Size"`
			}
			out := struct {
				XMLName     xml.Name `xml:"ListBucketResult"`
				Contents    []c      `xml:"Contents"`
				IsTruncated bool     `xml:"IsTruncated"`
			}{}
			for _, k := range keys {
				out.Contents = append(out.Contents, c{Key: k, LastModified: "2026-09-05T04:38:07.000Z", Size: int64(len(m.objects[k]))})
			}
			w.Header().Set("Content-Type", "application/xml")
			_ = xml.NewEncoder(w).Encode(out)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, "/"+m.bucket+"/")
		m.mu.Lock()
		m.gets = append(m.gets, key)
		body, ok := m.objects[key]
		code := m.getFail[key]
		m.mu.Unlock()
		if m.onGet != nil {
			m.onGet(key)
		}
		if code != 0 {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code><Message>no</Message></Error>`))
			return
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *s3Mock) snapshot() (lists, prefixes, gets []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.lists...), append([]string{}, m.prefixes...), append([]string{}, m.gets...)
}

func (m *s3Mock) cfg(name, format, prefix, state string) S3Config {
	return S3Config{Name: name, Endpoint: m.srv.URL + "/", Region: "ru-central1", Bucket: m.bucket, Prefix: prefix,
		AccessKey: "AK", SecretKey: "SK", Format: format, Interval: "1ms", StateFile: state}
}

// runUntil — крутит Run, пока emit не насчитает want событий (или не истечёт срок), возвращает собранное.
func runUntil(t *testing.T, s *S3, want int, extra func(e model.Event)) []model.Event {
	t.Helper()
	var mu sync.Mutex
	var got []model.Event
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Emit = func(e model.Event) {
		mu.Lock()
		got = append(got, e)
		n := len(got)
		mu.Unlock()
		if extra != nil {
			extra(e)
		}
		if n >= want {
			cancel()
		}
	}
	s.Run(ctx)
	if ctx.Err() == context.DeadlineExceeded {
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("за 5 с собрано %d событий из %d: %+v", len(got), want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	return got
}

const evA1 = `{"ts":"2026-09-05 04:38:07.000","source":"cloud.vk","source_class":"k8s","action":"iam.key.create","actor_name":"svc-ci","outcome":"success"}`
const evA2 = `{"ts":"2026-09-05 04:39:07.000","action":"vm.delete","actor_name":"i.petrov","severity":5}`
const evB1 = `{"ts":"2026-09-05 05:00:00.000","action":"vm.start","actor_name":"ops"}`

func TestS3RunListsFetchesAndSavesState(t *testing.T) {
	m := newS3Mock(t, map[string]string{
		"trails/2026/a.json": evA1 + "\n" + evA2 + "\n",
		"trails/2026/empty":  "",
		"trails/2026/b.json": "\n" + evB1 + "\n   \nnot json\n",
		"other/skip.json":    evB1 + "\n",
	})
	state := filepath.Join(t.TempDir(), "s3.state")
	s := NewS3(m.cfg("cloud.test", "events", "trails/", state), nil)
	got := runUntil(t, s, 3, nil)

	if got[0].Source != "cloud.vk" || got[0].ActorName != "svc-ci" {
		t.Fatalf("source из строки сохраняется: %+v", got[0])
	}
	if got[1].Source != "cloud.test" || got[1].Severity != 5 || got[1].Outcome != "unknown" || got[1].ActorKind != "unknown" {
		t.Fatalf("пустой source → имя источника, Ensure заполняет outcome/actor_kind: %+v", got[1])
	}
	if got[2].Action != "vm.start" {
		t.Fatalf("третье событие из b.json: %+v", got[2])
	}
	lists, prefixes, gets := m.snapshot()
	if len(lists) == 0 || lists[0] != "" || prefixes[0] != "trails/" {
		t.Fatalf("первый листинг — без start-after, с prefix: %v %v", lists, prefixes)
	}
	// Пустой объект не скачивается, чужой префикс не виден.
	for _, g := range gets {
		if g == "trails/2026/empty" || strings.HasPrefix(g, "other/") {
			t.Fatalf("лишнее скачивание %q: %v", g, gets)
		}
	}
	if b, _ := os.ReadFile(state); strings.TrimSpace(string(b)) != "trails/2026/b.json" {
		t.Fatalf("состояние — последний обработанный ключ: %q", b)
	}
	if m.badSigned.Load() != 0 {
		t.Fatalf("неподписанных запросов: %d", m.badSigned.Load())
	}
}

func TestS3RunResumesAfterStateKey(t *testing.T) {
	m := newS3Mock(t, map[string]string{
		"trails/a.json": evA1 + "\n",
		"trails/b.json": evB1 + "\n",
	})
	state := filepath.Join(t.TempDir(), "s3.state")
	if err := os.WriteFile(state, []byte("trails/a.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewS3(m.cfg("", "events", "trails/", state), nil)
	got := runUntil(t, s, 1, nil)
	if got[0].Action != "vm.start" {
		t.Fatalf("после a.json должен прийти только b.json: %+v", got)
	}
	lists, _, gets := m.snapshot()
	if lists[0] != "trails/a.json" {
		t.Fatalf("start-after из файла состояния: %v", lists)
	}
	for _, g := range gets {
		if g == "trails/a.json" {
			t.Fatal("уже обработанный объект скачан повторно")
		}
	}
	if s.cfg.Name != "cloud.events" {
		t.Fatalf("имя по умолчанию cloud.<format>: %q", s.cfg.Name)
	}
}

func TestS3RunYandexAuditFormat(t *testing.T) {
	ok := `{"event_id":"e1","event_source":"iam","event_type":"yandex.cloud.audit.iam.CreateAccessKey","event_time":"2026-09-05T04:38:07.120Z","event_status":"DONE","authentication":{"subject_type":"SERVICE_ACCOUNT","subject_name":"sa-ci","subject_id":"aje1"},"authorization":{"authorized":true},"resource_metadata":{"path":[{"resource_type":"resource-manager.folder","resource_id":"f1"}]},"request_metadata":{"remote_address":"10.0.5.5","user_agent":"yc"}}`
	deny := `{"event_id":"e2","event_source":"compute","event_type":"yandex.cloud.audit.compute.DeleteInstance","event_time":"2026-09-05T04:40:00Z","event_status":"ERROR","authentication":{"subject_type":"ANONYMOUS","subject_name":"anon"},"authorization":{"authorized":false},"resource_metadata":{"path":[]},"request_metadata":{"remote_address":"203.0.113.9"}}`
	errSt := `{"event_id":"e3","event_source":"compute","event_type":"yandex.cloud.audit.compute.StopInstance","event_time":"bad time","event_status":"ERROR","authentication":{"subject_type":"YANDEX_PASSPORT_USER_ACCOUNT","subject_name":"i.petrov"},"authorization":{"authorized":true}}`
	m := newS3Mock(t, map[string]string{"t/1.json": ok + "\n" + deny + "\n" + `{"no":"event_type"}` + "\n" + errSt + "\n"})
	s := NewS3(m.cfg("", "yandex-audit", "", ""), nil)
	got := runUntil(t, s, 3, nil)

	if got[0].ActorKind != "service" || got[0].Action != "yc.iam.createaccesskey" || got[0].Outcome != "success" || got[0].Object != "resource-manager.folder/f1" || got[0].SessionID != "e1" {
		t.Fatalf("сервисная учётка: %+v", got[0])
	}
	if got[1].Outcome != "deny" || got[1].Severity != 6 || got[1].ActorKind != "unknown" || got[1].SrcIP != "203.0.113.9" {
		t.Fatalf("неавторизованный запрос — deny/6: %+v", got[1])
	}
	if got[2].Outcome != "failure" || got[2].Severity != 3 || got[2].ActorKind != "user" || got[2].TS == "" {
		t.Fatalf("ERROR — failure/3, кривое время заменяется: %+v", got[2])
	}
	if s.cfg.Name != "cloud.yandex-audit" || got[0].Source != "cloud.yandex" {
		t.Fatalf("имя источника из парсера приоритетнее: cfg=%q src=%q", s.cfg.Name, got[0].Source)
	}
}

func TestParseYandexAuditEdgeCases(t *testing.T) {
	if _, err := ParseYandexAudit([]byte(`{"event_id":"x"}`)); err == nil {
		t.Fatal("без event_type — не запись Audit Trails")
	}
	if _, err := ParseYandexAudit([]byte(`garbage`)); err == nil {
		t.Fatal("мусор должен давать ошибку")
	}
	// delete при успехе поднимает серьёзность до 5; имя ресурса предпочтительнее id
	e, err := ParseYandexAudit([]byte(`{"event_type":"yandex.cloud.audit.compute.DeleteInstance","event_status":"DONE","authentication":{"subject_type":"FEDERATED_USER_ACCOUNT","subject_name":"u"},"authorization":{"authorized":true},"resource_metadata":{"path":[{"resource_type":"compute.instance","resource_id":"i1","resource_name":"web-01"}]}}`))
	if err != nil || e.Severity != 5 || e.Object != "compute.instance/web-01" || e.Outcome != "success" {
		t.Fatalf("%v %+v", err, e)
	}
	// deny + accessbinding: deny даёт 6, iam_change не понижает
	e, _ = ParseYandexAudit([]byte(`{"event_type":"yandex.cloud.audit.iam.SetAccessBindings","authentication":{"subject_type":"SERVICE_ACCOUNT"},"authorization":{"authorized":false}}`))
	if e.Severity != 6 || e.Attrs["iam_change"] != "true" || e.Outcome != "deny" {
		t.Fatalf("%+v", e)
	}
}

func TestS3ListErrorIsRetriedNextInterval(t *testing.T) {
	m := newS3Mock(t, map[string]string{"t/a.json": evA1 + "\n"})
	m.listCode.Store(http.StatusInternalServerError)
	s := NewS3(m.cfg("", "events", "", ""), nil)
	// После трёх неудачных листингов «починить» хранилище.
	go func() {
		for m.listCalls.Load() < 3 {
			time.Sleep(time.Millisecond)
		}
		m.listCode.Store(0)
	}()
	got := runUntil(t, s, 1, nil)
	if got[0].ActorName != "svc-ci" {
		t.Fatalf("%+v", got)
	}
	if m.listCalls.Load() < 4 {
		t.Fatalf("ошибка листинга не должна останавливать опрос: %d листингов", m.listCalls.Load())
	}
}

func TestS3FetchErrorStopsBatchAndKeepsState(t *testing.T) {
	m := newS3Mock(t, map[string]string{
		"t/a.json": evA1 + "\n",
		"t/b.json": evB1 + "\n",
		"t/c.json": evB1 + "\n",
	})
	m.getFail["t/b.json"] = http.StatusForbidden
	state := filepath.Join(t.TempDir(), "s3.state")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.onGet = func(key string) {
		if key == "t/b.json" {
			cancel() // первая же ошибка на b — хватит
		}
	}
	var got atomic.Int32
	s := NewS3(m.cfg("", "events", "", state), func(model.Event) { got.Add(1) })
	s.Run(ctx)
	if got.Load() != 1 {
		t.Fatalf("после ошибки на b.json объект c.json в этом раунде не читается: событий %d", got.Load())
	}
	_, _, gets := m.snapshot()
	for _, g := range gets {
		if g == "t/c.json" {
			t.Fatal("c.json скачан после ошибки на b.json — порядок ключей нарушен")
		}
	}
	if b, _ := os.ReadFile(state); strings.TrimSpace(string(b)) != "t/a.json" {
		t.Fatalf("состояние остаётся на последнем успешном ключе: %q", b)
	}
}

func TestS3GetReportsStatusAndBody(t *testing.T) {
	m := newS3Mock(t, map[string]string{})
	m.getFail["t/x.json"] = http.StatusForbidden
	s := NewS3(m.cfg("", "events", "", ""), nil)
	_, err := s.get(context.Background(), "/t/x.json", nil)
	if err == nil || !strings.Contains(err.Error(), "s3 403") || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("%v", err)
	}
	if _, err := s.fetch(context.Background(), "/t/missing.json"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("ключ со слэшем в начале нормализуется, 404 — ошибка: %v", err)
	}
	// Неподписанный клиент получает 403 от «хранилища» — проверка, что мок действительно требует подпись.
	bad := NewS3(S3Config{Endpoint: m.srv.URL, Bucket: "audit", AccessKey: "OTHER", SecretKey: "x"}, nil)
	if _, err := bad.list(context.Background(), ""); err == nil || m.badSigned.Load() != 1 {
		t.Fatalf("%v badSigned=%d", err, m.badSigned.Load())
	}
}

func TestS3RunDisabledWithoutCredentials(t *testing.T) {
	for _, cfg := range []S3Config{
		{Bucket: "b", SecretKey: "s"},
		{Bucket: "b", AccessKey: "a"},
		{AccessKey: "a", SecretKey: "s"},
	} {
		s := NewS3(cfg, func(model.Event) { t.Fatal("источник выключен") })
		done := make(chan struct{})
		go func() { s.Run(context.Background()); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatalf("Run должен вернуться сразу: %+v", cfg)
		}
	}
}

func TestNewS3Defaults(t *testing.T) {
	s := NewS3(S3Config{Bucket: "b"}, nil)
	if s.cfg.Region != "ru-central1" || s.cfg.Format != "events" || s.cfg.Name != "cloud.events" {
		t.Fatalf("%+v", s.cfg)
	}
	s = NewS3(S3Config{Bucket: "b", Region: "eu-1", Format: "yandex-audit", Name: "yc.prod"}, nil)
	if s.cfg.Region != "eu-1" || s.cfg.Format != "yandex-audit" || s.cfg.Name != "yc.prod" {
		t.Fatalf("%+v", s.cfg)
	}
	if s.loadState() != "" {
		t.Fatal("без state_file состояние пустое")
	}
	s.saveState("k") // без файла — no-op, без паники
}

func TestS3StateFileRoundTrip(t *testing.T) {
	state := filepath.Join(t.TempDir(), "st")
	s := NewS3(S3Config{Bucket: "b", StateFile: state}, nil)
	s.saveState("trails/2026/x.json")
	if got := s.loadState(); got != "trails/2026/x.json" {
		t.Fatalf("%q", got)
	}
	st, err := os.Stat(state)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("файл состояния 0600: %v %v", err, st.Mode())
	}
}

func TestS3RunInvalidIntervalFallsBackToMinute(t *testing.T) {
	// Некорректный interval → минута: за 300 мс второго листинга быть не должно.
	m := newS3Mock(t, map[string]string{})
	cfg := m.cfg("", "events", "", "")
	cfg.Interval = "soon"
	s := NewS3(cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if lists, _, _ := m.snapshot(); len(lists) != 1 {
		t.Fatalf("листингов %d, ожидался один (интервал по умолчанию — минута)", len(lists))
	}
}

func TestS3ListPassesPrefixAndStartAfter(t *testing.T) {
	m := newS3Mock(t, map[string]string{"p/1": "x", "p/2": "y", "q/3": "z"})
	s := NewS3(m.cfg("", "events", "p/", ""), nil)
	lr, err := s.list(context.Background(), "p/1")
	if err != nil || len(lr.Contents) != 1 || lr.Contents[0].Key != "p/2" || lr.Contents[0].Size != 1 {
		t.Fatalf("%v %+v", err, lr)
	}
	lists, prefixes, _ := m.snapshot()
	if fmt.Sprint(lists) != "[p/1]" || fmt.Sprint(prefixes) != "[p/]" {
		t.Fatalf("%v %v", lists, prefixes)
	}
}

// Сжатый объект (*.json.gz) читается прозрачно: распознаётся по магическим байтам gzip.
func TestS3FetchGzipTransparent(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(`{"source":"s3.gz","action":"a1"}` + "\n" + `{"source":"s3.gz","action":"a2"}` + "\n"))
	_ = zw.Close()
	m := newS3Mock(t, map[string]string{"logs/a.json.gz": buf.String(), "logs/b.json": `{"source":"s3.plain","action":"a3"}` + "\n"})
	src := NewS3(m.cfg("gz", "events", "logs/", filepath.Join(t.TempDir(), "state")), nil)
	got := runUntil(t, src, 3, nil)
	actions := map[string]bool{}
	for _, e := range got {
		actions[e.Action] = true
	}
	if !actions["a1"] || !actions["a2"] || !actions["a3"] {
		t.Fatalf("события из gzip и из обычного объекта: %v", actions)
	}
}
