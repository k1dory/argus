package pull

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Разбор событий потока: типы, которых нет в TestFalconDetection, маппинг
// серьёзности и вид субъекта.
func TestFalconParseVariants(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		action   string
		outcome  string
		severity uint8
		actor    string
		kind     string
		object   string
		attrs    map[string]string
	}{
		{
			name:     "инцидент — объект IncidentId, состояние и балл в attrs",
			line:     `{"metadata":{"eventType":"IncidentSummaryEvent","eventCreationTime":1757066138000},"event":{"IncidentId":"inc:abc","State":"open","FineScore":73}}`,
			action:   "threat.incident",
			outcome:  "detected",
			severity: 8,
			kind:     "unknown",
			object:   "inc:abc",
			attrs:    map[string]string{"state": "open", "fine_score": "73"},
		},
		{
			name:     "аудит — успешная операция, субъект пользователь",
			line:     `{"metadata":{"eventType":"UserActivityAuditEvent","eventCreationTime":1757066138000},"event":{"UserId":"ops@corp.local","UserIp":"10.1.1.1","OperationName":" CreateAPIClient ","ServiceName":"API Clients","Success":true}}`,
			action:   "falcon.createapiclient",
			outcome:  "success",
			severity: 0,
			actor:    "ops@corp.local",
			kind:     "user",
			object:   "API Clients",
			attrs:    map[string]string{"operation": " CreateAPIClient "},
		},
		{
			name:     "неизвестный тип — действие falcon.<тип>, результат unknown от Ensure",
			line:     `{"metadata":{"eventType":"RemoteResponseSessionStartEvent","eventCreationTime":1757066138000},"event":{"UserName":"SYSTEM"}}`,
			action:   "falcon.remoteresponsesessionstartevent",
			outcome:  "unknown",
			severity: 0,
			kind:     "unknown",
		},
		{
			name:     "детект: машинная учётка с $ — system",
			line:     `{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000},"event":{"ComputerName":"SRV-1","UserName":"SRV-1$","SeverityName":"Critical","FileName":"x.exe"}}`,
			action:   "threat.detect",
			outcome:  "detected",
			severity: 10,
			actor:    "SRV-1$",
			kind:     "system",
			object:   "x.exe",
		},
		{
			name:     "детект: NT AUTHORITY\\SYSTEM — system по подстроке",
			line:     `{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000},"event":{"UserName":"NT AUTHORITY\\System","SeverityName":"Medium"}}`,
			action:   "threat.detect",
			outcome:  "detected",
			severity: 5,
			actor:    "NT AUTHORITY\\System",
			kind:     "system",
		},
		{
			name:     "детект: Low → 3",
			line:     `{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000},"event":{"SeverityName":"Low"}}`,
			action:   "threat.detect",
			outcome:  "detected",
			severity: 3,
			kind:     "unknown",
		},
		{
			name:     "детект: Informational и пустая серьёзность → 2",
			line:     `{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000},"event":{"SeverityName":"Informational"}}`,
			action:   "threat.detect",
			outcome:  "detected",
			severity: 2,
			kind:     "unknown",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := ParseFalconEvent([]byte(c.line))
			if err != nil {
				t.Fatalf("ошибка разбора: %v", err)
			}
			if e.Action != c.action || e.Outcome != c.outcome || e.Severity != c.severity || e.ActorName != c.actor || e.ActorKind != c.kind || e.Object != c.object {
				t.Fatalf("action=%q outcome=%q sev=%d actor=%q kind=%q object=%q: %+v", e.Action, e.Outcome, e.Severity, e.ActorName, e.ActorKind, e.Object, e)
			}
			for k, v := range c.attrs {
				if e.Attrs[k] != v {
					t.Fatalf("attrs[%s]=%q, ожидалось %q", k, e.Attrs[k], v)
				}
			}
			if e.Source != "edr.crowdstrike" || e.SourceClass != "edr" || e.Raw != c.line {
				t.Fatalf("источник/raw: %+v", e)
			}
			if e.TS != "2025-09-05 09:55:38.000" {
				t.Fatalf("ts из eventCreationTime: %s", e.TS)
			}
		})
	}
}

func TestFalconParseRejectsGarbageAndFillsTime(t *testing.T) {
	for _, bad := range []string{``, `not json`, `{"metadata":{},"event":{}}`, `{"metadata":{"offset":1},"event":{"a":1}}`} {
		if _, err := ParseFalconEvent([]byte(bad)); err == nil {
			t.Fatalf("ожидалась ошибка на %q", bad)
		}
	}
	// Без eventCreationTime время ставит Ensure — «сейчас», а не пусто и не 1970.
	e, err := ParseFalconEvent([]byte(`{"metadata":{"eventType":"DetectionSummaryEvent","offset":7},"event":{}}`))
	if err != nil || e.TS == "" || strings.HasPrefix(e.TS, "1970") {
		t.Fatalf("%v ts=%q", err, e.TS)
	}
	if e.Attrs["offset"] != "7" || e.Attrs["event_type"] != "DetectionSummaryEvent" {
		t.Fatalf("attrs: %v", e.Attrs)
	}
	// detect: null-значения не превращаются в строку "<nil>"
	e, _ = ParseFalconEvent([]byte(`{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000},"event":{"ComputerName":null,"UserName":null}}`))
	if e.Node != "" || e.ActorName != "" {
		t.Fatalf("null должен давать пустую строку: node=%q actor=%q", e.Node, e.ActorName)
	}
}

func TestNewFalconDefaults(t *testing.T) {
	f := NewFalcon(FalconConfig{ClientID: "id", ClientSecret: "s"}, nil)
	if f.cfg.BaseURL != "https://api.crowdstrike.com" || f.cfg.AppID != "argus" {
		t.Fatalf("дефолты: %+v", f.cfg)
	}
	f = NewFalcon(FalconConfig{BaseURL: "https://api.eu-1.crowdstrike.com/", AppID: "siem"}, nil)
	if f.cfg.BaseURL != "https://api.eu-1.crowdstrike.com/" || f.cfg.AppID != "siem" {
		t.Fatalf("заданные значения не должны меняться: %+v", f.cfg)
	}
}

// falconAPI — имитация CrowdStrike: OAuth2, discovery потока, сам поток.
type falconAPI struct {
	srv        *httptest.Server
	mu         sync.Mutex
	tokens     atomic.Int32 // выданных токенов
	discovers  atomic.Int32
	streams    atomic.Int32
	oauthCode  int    // 0 → 200
	discCode   int    // 0 → 200
	discBody   string // непустое — отдать как есть
	streamURL  string // непустое — подменить dataFeedURL
	lines      []string
	lastOAuth  http.Header
	lastOAuthF map[string]string
	lastDisc   *http.Request
	lastStream http.Header
}

func newFalconAPI(t *testing.T, lines ...string) *falconAPI {
	a := &falconAPI{lines: lines}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		a.mu.Lock()
		a.lastOAuth = r.Header.Clone()
		a.lastOAuthF = map[string]string{"client_id": r.PostForm.Get("client_id"), "client_secret": r.PostForm.Get("client_secret")}
		a.mu.Unlock()
		if a.oauthCode != 0 {
			w.WriteHeader(a.oauthCode)
			_, _ = w.Write([]byte(`{"errors":[{"code":401,"message":"access denied"}]}`))
			return
		}
		n := a.tokens.Add(1)
		_, _ = fmt.Fprintf(w, `{"access_token":"tok-%d","expires_in":1799}`, n)
	})
	mux.HandleFunc("/sensors/entities/datafeed/v2", func(w http.ResponseWriter, r *http.Request) {
		a.discovers.Add(1)
		a.mu.Lock()
		a.lastDisc = r.Clone(context.Background())
		a.mu.Unlock()
		if a.discCode != 0 {
			w.WriteHeader(a.discCode)
			_, _ = w.Write([]byte(`{"errors":[{"code":403,"message":"access denied"}]}`))
			return
		}
		if a.discBody != "" {
			_, _ = w.Write([]byte(a.discBody))
			return
		}
		feed := a.streamURL
		if feed == "" {
			feed = a.srv.URL + "/sensors/entities/datafeed/v2/stream?partition=0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []map[string]any{{
			"dataFeedURL":  feed,
			"sessionToken": map[string]string{"token": "sess-1"},
		}}})
	})
	mux.HandleFunc("/sensors/entities/datafeed/v2/stream", func(w http.ResponseWriter, r *http.Request) {
		a.streams.Add(1)
		a.mu.Lock()
		a.lastStream = r.Header.Clone()
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		for _, l := range a.lines {
			_, _ = fmt.Fprintln(w, l)
		}
	})
	a.srv = httptest.NewServer(mux)
	t.Cleanup(a.srv.Close)
	return a
}

func collectFalcon(t *testing.T, api *falconAPI) (*Falcon, *[]model.Event, *sync.Mutex) {
	var mu sync.Mutex
	var got []model.Event
	f := NewFalcon(FalconConfig{BaseURL: api.srv.URL + "/", ClientID: "cid", ClientSecret: "sec", AppID: "argus-test"}, func(e model.Event) {
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
	})
	return f, &got, &mu
}

func TestFalconTokenRequestAndErrors(t *testing.T) {
	api := newFalconAPI(t)
	f, _, _ := collectFalcon(t, api)
	tok, err := f.token(context.Background())
	if err != nil || tok != "tok-1" {
		t.Fatalf("%v %q", err, tok)
	}
	api.mu.Lock()
	ct, form := api.lastOAuth.Get("Content-Type"), api.lastOAuthF
	api.mu.Unlock()
	if ct != "application/x-www-form-urlencoded" || form["client_id"] != "cid" || form["client_secret"] != "sec" {
		t.Fatalf("форма OAuth2: ct=%q %v", ct, form)
	}

	api.oauthCode = http.StatusUnauthorized
	if _, err := f.token(context.Background()); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("401 должен давать ошибку со статусом: %v", err)
	}
	// Недоступный сервер — ошибка транспорта, а не паника.
	dead := NewFalcon(FalconConfig{BaseURL: "http://127.0.0.1:1", ClientID: "a", ClientSecret: "b"}, nil)
	if _, err := dead.token(context.Background()); err == nil {
		t.Fatal("ожидалась ошибка соединения")
	}
}

func TestFalconOnceStreamsEvents(t *testing.T) {
	api := newFalconAPI(t,
		`{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000,"offset":1},"event":{"ComputerName":"WKS-1","SeverityName":"High"}}`,
		``,
		`   `,
		`garbage line`,
		`{"metadata":{"eventType":"AuthActivityAuditEvent","eventCreationTime":1757066139000,"offset":2},"event":{"UserId":"u","OperationName":"userAuthenticate","Success":"false"}}`,
	)
	f, got, mu := collectFalcon(t, api)
	err := f.once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "falcon stream closed") {
		t.Fatalf("закрытие потока — ошибка для переподключения: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) != 2 || (*got)[0].Node != "WKS-1" || (*got)[1].Outcome != "failure" {
		t.Fatalf("события: %+v", *got)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.lastDisc.Header.Get("Authorization") != "Bearer tok-1" || api.lastDisc.URL.Query().Get("appId") != "argus-test" {
		t.Fatalf("discovery: %s %s", api.lastDisc.Header.Get("Authorization"), api.lastDisc.URL.RawQuery)
	}
	if api.lastStream.Get("Authorization") != "Token sess-1" || api.lastStream.Get("Accept") != "application/json" {
		t.Fatalf("поток: %v", api.lastStream)
	}
}

func TestFalconOnceErrors(t *testing.T) {
	t.Run("discovery 403", func(t *testing.T) {
		api := newFalconAPI(t)
		api.discCode = http.StatusForbidden
		f, _, _ := collectFalcon(t, api)
		err := f.once(context.Background())
		if err == nil || !strings.Contains(err.Error(), "falcon discover: 403") || !strings.Contains(err.Error(), "access denied") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("discovery без потоков", func(t *testing.T) {
		api := newFalconAPI(t)
		api.discBody = `{"resources":[]}`
		f, _, _ := collectFalcon(t, api)
		if err := f.once(context.Background()); err == nil || !strings.Contains(err.Error(), "falcon discover") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("discovery не JSON", func(t *testing.T) {
		api := newFalconAPI(t)
		api.discBody = `<html>maintenance</html>`
		f, _, _ := collectFalcon(t, api)
		if err := f.once(context.Background()); err == nil || !strings.Contains(err.Error(), "maintenance") {
			t.Fatalf("тело ошибки должно попадать в сообщение: %v", err)
		}
	})
	t.Run("поток недоступен", func(t *testing.T) {
		api := newFalconAPI(t)
		api.streamURL = "http://127.0.0.1:1/stream"
		f, _, _ := collectFalcon(t, api)
		if err := f.once(context.Background()); err == nil || strings.Contains(err.Error(), "stream closed") {
			t.Fatalf("ошибка соединения с потоком: %v", err)
		}
	})
	t.Run("oauth отказ — до discovery не доходим", func(t *testing.T) {
		api := newFalconAPI(t)
		api.oauthCode = http.StatusForbidden
		f, _, _ := collectFalcon(t, api)
		if err := f.once(context.Background()); err == nil || api.discovers.Load() != 0 {
			t.Fatalf("%v discovers=%d", err, api.discovers.Load())
		}
	})
}

func TestFalconRunReconnectsWithFreshToken(t *testing.T) {
	api := newFalconAPI(t, `{"metadata":{"eventType":"DetectionSummaryEvent","eventCreationTime":1757066138000},"event":{"SeverityName":"Low"}}`)
	f, got, mu := collectFalcon(t, api)
	f.Delay = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for api.streams.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run не завершился по отмене контекста")
	}
	if api.streams.Load() < 3 || api.tokens.Load() < 3 {
		t.Fatalf("каждое переподключение берёт новый токен: streams=%d tokens=%d", api.streams.Load(), api.tokens.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(*got) < 3 {
		t.Fatalf("событий %d", len(*got))
	}
}

func TestFalconRunStopsDuringBackoff(t *testing.T) {
	api := newFalconAPI(t)
	api.oauthCode = http.StatusUnauthorized
	f, _, _ := collectFalcon(t, api)
	f.Delay = time.Hour // отмена контекста должна прервать ожидание, а не ждать час
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run не вышел из паузы по ctx.Done")
	}
}

func TestFalconRunDisabledWithoutCredentials(t *testing.T) {
	api := newFalconAPI(t)
	f := NewFalcon(FalconConfig{BaseURL: api.srv.URL}, func(model.Event) {
		t.Fatal("источник выключен — событий быть не должно")
	})
	done := make(chan struct{})
	go func() { f.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("без client_id/secret Run должен вернуться сразу")
	}
	if api.tokens.Load() != 0 {
		t.Fatal("запросов к API быть не должно")
	}
}
