package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// recordingConsole — консоль, запоминающая полный запрос последнего вызова и
// отвечающая тем, что задано в тесте: статус, тело, заголовок Content-Type.
type recordingConsole struct {
	mu     sync.Mutex
	path   string
	query  url.Values
	auth   string
	status int
	body   string
	ctype  string
}

func (c *recordingConsole) handler(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.path, c.query, c.auth = r.URL.Path, r.URL.Query(), r.Header.Get("Authorization")
	status, body, ctype := c.status, c.body, c.ctype
	c.mu.Unlock()
	if ctype != "" {
		w.Header().Set("Content-Type", ctype)
	}
	if status != 0 {
		w.WriteHeader(status)
	}
	_, _ = w.Write([]byte(body))
}

func (c *recordingConsole) set(status int, body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status, c.body = status, body
}

func (c *recordingConsole) last() (string, url.Values) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.path, c.query
}

// newRecordingSession — MCP-сессия через in-memory транспорт к серверу с
// записывающей консолью; профиль по умолчанию задаётся именем.
func newRecordingSession(t *testing.T, profileName string) (*session, *recordingConsole) {
	t.Helper()
	con := &recordingConsole{body: `{"rows":[],"total":0,"page":1,"pageSize":50,"series":[],"facets":[],"error":null,"ms":1}`}
	srv := httptest.NewServer(http.HandlerFunc(con.handler))
	t.Cleanup(srv.Close)
	ps, err := newProfiles(profileName, []byte("pseudonym-key-for-tests-0123456789"), []string{canary}, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := newServer(&client{base: srv.URL, token: "api-token", http: srv.Client()}, ps)
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	ss, err := server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ss.Close() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return &session{t: t, cs: cs, con: &fakeConsole{}}, con
}

func TestEnv(t *testing.T) {
	t.Setenv("ARGUS_TEST_ENV_X", "")
	if got := env("ARGUS_TEST_ENV_X", "def"); got != "def" {
		t.Fatalf("пустая переменная → умолчание, получено %q", got)
	}
	t.Setenv("ARGUS_TEST_ENV_X", "set")
	if got := env("ARGUS_TEST_ENV_X", "def"); got != "set" {
		t.Fatalf("заданная переменная: %q", got)
	}
}

func TestTrimAddsEllipsis(t *testing.T) {
	if got := trim("  short ", 10); got != "short" {
		t.Fatalf("короткая строка только обрезается по пробелам: %q", got)
	}
	long := strings.Repeat("a", 20)
	if got := trim(long, 5); got != "aaaaa…" {
		t.Fatalf("длинная строка: %q", got)
	}
}

func TestIsOne(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want bool
	}{
		{json.Number("1"), true}, {json.Number("2"), false}, {json.Number("1.0"), false},
		{float64(1), true}, {float64(0), false},
		{"1", true}, {"0", false}, {"true", false},
		{true, true}, {false, false},
		{nil, false}, {[]any{1}, false}, {map[string]any{}, false},
	} {
		if got := isOne(tc.v); got != tc.want {
			t.Errorf("isOne(%#v) = %v, ожидалось %v", tc.v, got, tc.want)
		}
	}
}

// profilesFromEnv: профиль по умолчанию, требования к ключу псевдонимов,
// канарейки через запятую, словарь имён из файла.
func TestProfilesFromEnv(t *testing.T) {
	longKey := strings.Repeat("k", minHTTPTokenLen)
	clear := func() {
		for _, k := range []string{"ARGUS_PSEUDONYM_KEY", "ARGUS_MCP_PROFILE", "ARGUS_MCP_TRIAGE_TOKEN", "ARGUS_REDACT_CANARIES", "ARGUS_REDACT_NAMES_FILE"} {
			t.Setenv(k, "")
		}
	}

	t.Run("пусто → full без ключа", func(t *testing.T) {
		clear()
		ps, err := profilesFromEnv()
		if err != nil || ps.def.name != profileFull {
			t.Fatalf("ps=%v err=%v", ps, err)
		}
		if len(ps.byName) != 2 {
			t.Fatalf("ожидались оба профиля: %v", ps.byName)
		}
	})
	t.Run("triage по умолчанию требует длинный ключ", func(t *testing.T) {
		clear()
		t.Setenv("ARGUS_MCP_PROFILE", " triage ")
		t.Setenv("ARGUS_PSEUDONYM_KEY", "short")
		if _, err := profilesFromEnv(); err == nil || !strings.Contains(err.Error(), "ARGUS_PSEUDONYM_KEY") {
			t.Fatalf("ожидалась ошибка короткого ключа: %v", err)
		}
		t.Setenv("ARGUS_PSEUDONYM_KEY", longKey)
		ps, err := profilesFromEnv()
		if err != nil || ps.def.name != profileTriage {
			t.Fatalf("ps=%v err=%v", ps, err)
		}
	})
	t.Run("токен triage при full тоже требует ключ", func(t *testing.T) {
		clear()
		t.Setenv("ARGUS_MCP_TRIAGE_TOKEN", "any")
		if _, err := profilesFromEnv(); err == nil {
			t.Fatal("ожидалась ошибка: ключ пуст, а профиль triage возможен по токену")
		}
		t.Setenv("ARGUS_PSEUDONYM_KEY", longKey)
		if _, err := profilesFromEnv(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("неизвестный профиль", func(t *testing.T) {
		clear()
		t.Setenv("ARGUS_MCP_PROFILE", "bogus")
		if _, err := profilesFromEnv(); err == nil || !strings.Contains(err.Error(), "ожидается full или triage") {
			t.Fatalf("ожидалась ошибка профиля: %v", err)
		}
	})
	t.Run("канарейки: обрезка, пустые элементы пропущены, действуют в редакции", func(t *testing.T) {
		clear()
		t.Setenv("ARGUS_REDACT_CANARIES", " ALPHA-CANARY , ,BETA-CANARY,")
		ps, err := profilesFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		got := ps.def.red.CanaryLiterals() // редактор хранит литералы в нижнем регистре
		if len(got) != 2 || !strings.EqualFold(got[0], "ALPHA-CANARY") || !strings.EqualFold(got[1], "BETA-CANARY") {
			t.Fatalf("канарейки: %q", got)
		}
		if out := ps.def.red.Text("log: ALPHA-CANARY seen"); strings.Contains(out, "ALPHA-CANARY") {
			t.Fatalf("канарейка не вырезана: %q", out)
		}
	})
	t.Run("файл имён: читается, отсутствие — ошибка", func(t *testing.T) {
		clear()
		t.Setenv("ARGUS_PSEUDONYM_KEY", longKey)
		t.Setenv("ARGUS_MCP_PROFILE", profileTriage)
		f := filepath.Join(t.TempDir(), "names.txt")
		if err := os.WriteFile(f, []byte("Иванов\nПетров\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("ARGUS_REDACT_NAMES_FILE", f)
		ps, err := profilesFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		// Фамилия из словаря в triage скрывается, незнакомая — нет.
		if out := ps.def.red.Text("экспорт для Иванов"); strings.Contains(out, "Иванов") {
			t.Fatalf("имя из словаря не скрыто: %q", out)
		}
		t.Setenv("ARGUS_REDACT_NAMES_FILE", filepath.Join(t.TempDir(), "missing.txt"))
		if _, err := profilesFromEnv(); err == nil || !strings.Contains(err.Error(), "ARGUS_REDACT_NAMES_FILE") {
			t.Fatalf("ожидалась ошибка чтения файла: %v", err)
		}
	})
}

// Набор инструментов и ресурс синтаксиса: каждое описание несёт предупреждение
// о недоверенном вводе, ресурс содержит разделы get_log и get_actor.
func TestNewServerToolsAndResource(t *testing.T) {
	s, _ := newRecordingSession(t, profileFull)
	ctx := context.Background()
	tools, err := s.cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"search_alerts": true, "search_events": true, "get_log": true, "list_incidents": true, "get_incident": true, "sources_health": true, "get_actor": true}
	for _, tool := range tools.Tools {
		if !want[tool.Name] {
			t.Errorf("лишний инструмент %q", tool.Name)
		}
		delete(want, tool.Name)
		if !strings.Contains(tool.Description, untrustedNotice) {
			t.Errorf("%s: описание без предупреждения о недоверенном вводе", tool.Name)
		}
	}
	if len(want) != 0 {
		t.Errorf("не зарегистрированы: %v", want)
	}
	res, err := s.cs.ListResources(ctx, nil)
	if err != nil || len(res.Resources) != 1 || res.Resources[0].URI != "argus://search-syntax" {
		t.Fatalf("ресурсы: %v %v", res, err)
	}
	rr, err := s.cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "argus://search-syntax"})
	if err != nil || len(rr.Contents) != 1 {
		t.Fatalf("чтение ресурса: %v %v", rr, err)
	}
	text := rr.Contents[0].Text
	for _, part := range []string{"get_log", "get_actor", "field:value", "attr.<ключ>"} {
		if !strings.Contains(text, part) {
			t.Errorf("в синтаксисе нет %q", part)
		}
	}
	if rr.Contents[0].MIMEType != "text/markdown" {
		t.Errorf("mime: %q", rr.Contents[0].MIMEType)
	}
}

// search_*: каждый параметр входа доходит до консоли своим именем; limit
// переключает в режим выгрузки с потолком maxExport и raw=0 без include_raw.
func TestSearchToolForwardsParams(t *testing.T) {
	s, con := newRecordingSession(t, profileFull)

	out, isErr := s.call("search_events", map[string]any{"query": "level>=5", "actor": "svc-ci", "range": "7d", "page": 3, "show_muted": true})
	if isErr {
		t.Fatalf("ошибка: %s", out)
	}
	path, q := con.last()
	if path != "/api/search" || q.Get("index") != "events" || q.Get("range") != "7d" || q.Get("page") != "3" || q.Get("muted") != "1" {
		t.Fatalf("параметры страницы: %s %v", path, q)
	}
	if !strings.Contains(q.Get("q"), "svc-ci") || !strings.HasSuffix(q.Get("q"), "level>=5") {
		t.Fatalf("строка запроса: фильтр перед DSL: %q", q.Get("q"))
	}
	if q.Has("format") || q.Has("limit") || q.Has("from") || q.Has("to") {
		t.Fatalf("без limit/from/to лишних параметров нет: %v", q)
	}
	if !strings.HasPrefix(out, untrustedNotice) {
		t.Fatalf("ответ без предупреждения: %q", out[:min(len(out), 80)])
	}

	// Точный интервал и выгрузка: limit выше потолка режется, raw=0 без include_raw.
	s.call("search_alerts", map[string]any{"from": "2026-08-01T00:00", "to": "2026-08-02T00:00", "limit": 10000, "rule_id": 5710})
	_, q = con.last()
	if q.Get("index") != "alerts" || q.Get("from") != "2026-08-01T00:00" || q.Get("to") != "2026-08-02T00:00" {
		t.Fatalf("интервал: %v", q)
	}
	if q.Get("format") != "export" || q.Get("limit") != "500" || q.Get("raw") != "0" {
		t.Fatalf("выгрузка: %v", q)
	}
	if !strings.Contains(q.Get("q"), "5710") {
		t.Fatalf("rule_id не в строке: %q", q.Get("q"))
	}

	// include_raw в full: raw остаётся, лимит в границах — как задан.
	s.call("search_events", map[string]any{"limit": 7, "include_raw": true})
	_, q = con.last()
	if q.Get("limit") != "7" || q.Has("raw") {
		t.Fatalf("include_raw: %v", q)
	}
}

// Ошибки консоли доходят до модели текстом с isError, тело ответа — нет.
func TestClientGetErrors(t *testing.T) {
	s, con := newRecordingSession(t, profileFull)
	for _, tc := range []struct {
		name, want string
		status     int
		body       string
		ctype      string
	}{
		{"401 — подсказка про токен", "401", http.StatusUnauthorized, `{"error":"unauthorized"}`, ""},
		{"500 с длинным телом обрезается", "консоль ответила 500", http.StatusInternalServerError, strings.Repeat("x", 700), ""},
		{"не JSON", "не JSON", http.StatusOK, "<html>login</html>", "text/html"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			con.mu.Lock()
			con.ctype = tc.ctype
			con.mu.Unlock()
			con.set(tc.status, tc.body)
			out, isErr := s.call("sources_health", nil)
			if !isErr || !strings.Contains(out, tc.want) {
				t.Fatalf("isErr=%v out=%q", isErr, out)
			}
			if tc.status == http.StatusInternalServerError && (strings.Contains(out, strings.Repeat("x", 600)) || !strings.Contains(out, "…")) {
				t.Fatalf("тело ошибки не обрезано до 500 символов: %d байт", len(out))
			}
			if tc.ctype != "" && !strings.Contains(out, tc.ctype) {
				t.Fatalf("Content-Type не назван: %q", out)
			}
		})
	}
	t.Run("ответ больше maxBody", func(t *testing.T) {
		con.mu.Lock()
		con.ctype = ""
		con.mu.Unlock()
		con.set(http.StatusOK, "["+strings.Repeat(" ", maxBody)+"]")
		out, isErr := s.call("sources_health", nil)
		if !isErr || !strings.Contains(out, "больше 16 МБ") {
			t.Fatalf("isErr=%v out=%q", isErr, out[:min(len(out), 200)])
		}
	})
	t.Run("консоль недоступна", func(t *testing.T) {
		dead := httptest.NewServer(http.NotFoundHandler())
		dead.Close()
		c := &client{base: dead.URL + "/", token: "x", http: http.DefaultClient}
		if _, err := c.get(context.Background(), "/api/sources", nil); err == nil || !strings.Contains(err.Error(), "недоступна") {
			t.Fatalf("ожидалась ошибка соединения: %v", err)
		}
		if _, err := c.get(context.Background(), "::bad path", nil); err == nil {
			t.Fatal("некорректный URL должен давать ошибку построения запроса")
		}
	})
}

// list_incidents и get_incident: фильтры уходят своими именами, идентификатор
// нормализуется, в triage q — только INC-N.
func TestIncidentTools(t *testing.T) {
	s, con := newRecordingSession(t, profileFull)
	con.set(0, `{"rows":[{"incident_id":"INC-5","status":"new","level":"high","owner":"duty"}],"total":1,"page":2,"pageSize":50}`)
	out, isErr := s.call("list_incidents", map[string]any{"status": "new", "level": "high", "q": "ssh", "page": 2})
	if isErr || !strings.Contains(out, "INC-5") {
		t.Fatalf("list_incidents: %v %s", isErr, out)
	}
	path, q := con.last()
	if path != "/api/incidents" || q.Get("status") != "new" || q.Get("level") != "high" || q.Get("q") != "ssh" || q.Get("page") != "2" {
		t.Fatalf("параметры: %s %v", path, q)
	}
	s.call("list_incidents", nil)
	_, q = con.last()
	if len(q) != 0 {
		t.Fatalf("без фильтров параметров нет: %v", q)
	}
	if _, isErr := s.call("get_incident", map[string]any{"id": " 7 "}); isErr {
		t.Fatal("get_incident по номеру")
	}
	path, _ = con.last()
	if path != "/api/incidents/INC-7" {
		t.Fatalf("идентификатор без префикса: %s", path)
	}
	s.call("get_incident", map[string]any{"id": "inc-9"})
	if path, _ = con.last(); path != "/api/incidents/INC-9" {
		t.Fatalf("регистр: %s", path)
	}
	// Ошибка консоли по карточке и по списку → isError.
	con.set(http.StatusNotFound, `{"error":"not_found"}`)
	if out, isErr := s.call("get_incident", map[string]any{"id": "404"}); !isErr || !strings.Contains(out, "404") {
		t.Fatalf("карточка 404: %v %s", isErr, out)
	}
	if _, isErr := s.call("list_incidents", map[string]any{"status": "new"}); !isErr {
		t.Fatal("список при ошибке консоли")
	}
	con.set(http.StatusBadGateway, "bad gateway")
	if _, isErr := s.call("get_log", map[string]any{"log": "ci"}); !isErr {
		t.Fatal("get_log при ошибке консоли")
	}

	ts, tcon := newRecordingSession(t, profileTriage)
	tcon.set(0, `{"rows":[],"total":0,"page":1,"pageSize":50}`)
	out, isErr = ts.call("list_incidents", map[string]any{"q": "petrov"})
	if !isErr || !strings.Contains(out, "только идентификатор INC-N") {
		t.Fatalf("triage q подстрокой: %v %s", isErr, out)
	}
	if _, isErr = ts.call("list_incidents", map[string]any{"q": " inc-12 "}); isErr {
		t.Fatal("triage q=INC-N разрешён")
	}
	if _, q = tcon.last(); q.Get("q") != " inc-12 " {
		t.Fatalf("q передан как есть: %q", q.Get("q"))
	}
}

// Форма alerts в triage: поля алерта остаются, лишняя колонка исчезает;
// sources_health рендерится по своей форме.
func TestTriageShapesAlertsAndSources(t *testing.T) {
	s, con := newRecordingSession(t, profileTriage)
	con.set(0, `{"rows":[{"time":"2026-08-14 04:01:38","rule_level":10,"rule_id":"5710","rule_description":"sshd: brute","agent_name":"ws-ivanov","srcip":"10.0.0.9","secret_extra":"`+leakedToken+`"}],
	 "total":1,"page":1,"pageSize":50,"series":[{"t":1,"n":1}],"facets":[{"field":"agent","label":"агент","values":[{"value":"ws-ivanov","count":1}]},{"field":"rule","label":"правило","values":[{"value":"5710","count":1}]}],"error":null,"ms":2}`)
	out, isErr := s.call("search_alerts", map[string]any{"rule_id": 5710})
	if isErr {
		t.Fatalf("ошибка: %s", out)
	}
	for _, want := range []string{`"rule_level":10`, `"rule_id":"5710"`, `"srcip":"10.0.0.9"`, `"field":"rule"`} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %s:\n%s", want, out)
		}
	}
	assertNoLeak(t, "alerts triage", out, "secret_extra", leakedToken, "ws-ivanov")
	if !strings.Contains(out, "host-") {
		t.Errorf("узел человека в фасете агентов должен стать псевдонимом host-…:\n%s", out)
	}

	con.set(0, `{"sources":[{"source":"telemetry.smoke","alive":true,"events_1m":3,"token":"`+leakedToken+`"}],"checked_at":"2026-08-14T05:00:00Z","extra":"x"}`)
	out, isErr = s.call("sources_health", nil)
	if isErr || !strings.Contains(out, "telemetry.smoke") || !strings.Contains(out, "checked_at") {
		t.Fatalf("sources_health: %v %s", isErr, out)
	}
	assertNoLeak(t, "sources triage", out, leakedToken, `"extra"`)
}

// render: невалидный JSON — ошибка инструмента, не сырое тело; pretriage по
// паспорту: виды алиасов, summary.nodes строками и объектами, нетипичные формы.
func TestRenderAndPretriageBranches(t *testing.T) {
	ps, err := newProfiles(profileTriage, []byte("pseudonym-key-for-tests-0123456789"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p := ps.def
	res, _, _ := p.render([]byte(`{"rows":[`), logShape, false)
	if !res.IsError {
		t.Fatal("битый JSON должен давать isError")
	}
	full := ps.byName[profileFull]
	res, _, _ = full.render([]byte(`{"items":[{"raw":"secret","ts":"x"}],"count":1}`), logShape, false)
	text := res.Content[0].(*mcp.TextContent).Text
	if strings.Contains(text, `"raw"`) {
		t.Fatalf("raw без include_raw должен удаляться и в full: %s", text)
	}
	res, _, _ = full.render([]byte(`{"items":[{"raw":"kept","ts":"x"}],"count":1}`), logShape, true)
	if !strings.Contains(res.Content[0].(*mcp.TextContent).Text, `"raw":"kept"`) {
		t.Fatal("include_raw в full сохраняет raw")
	}

	// pretriage не падает на не-объекте и на списках не того типа.
	p.pretriage([]any{"x"})
	p.pretriage(map[string]any{"rows": "not-a-list", "aliases": []any{"str", map[string]any{"value": 1}}, "summary": map[string]any{"nodes": "x"}, "facets": []any{"str", map[string]any{"field": "rule", "values": []any{map[string]any{"value": "5710"}}}}})

	doc := map[string]any{
		"items": []any{
			map[string]any{"pii": json.Number("1"), "object": "паспорт 4510", "attrs": map[string]any{"a": 1}},
			map[string]any{"pii": json.Number("0"), "object": "ok"},
			"not-a-row",
		},
		"aliases": []any{
			map[string]any{"kind": "ip", "value": "10.77.0.42"},
			map[string]any{"kind": "host", "value": "ws-ivanov"},
			map[string]any{"kind": "email", "value": "ivan@example.invalid"},
			map[string]any{"kind": "badge", "value": "B-123"},
		},
		"summary": map[string]any{"nodes": []any{"ws-ivanov", map[string]any{"node": "ws-petrov", "count": 2}, 7}},
		"facets":  []any{map[string]any{"field": "actor", "values": []any{map[string]any{"value": "i.petrov", "count": 1}, "str"}}},
	}
	p.pretriage(doc)
	items := doc["items"].([]any)
	if r := items[0].(map[string]any); r["object"] != piiMasked || r["attrs"] != piiMasked {
		t.Fatalf("строка с pii=1 не скрыта: %v", r)
	}
	if r := items[1].(map[string]any); r["object"] != "ok" {
		t.Fatalf("строка без pii изменена: %v", r)
	}
	al := doc["aliases"].([]any)
	if al[0].(map[string]any)["value"] != "10.77.0.42" {
		t.Error("IP-алиас должен остаться")
	}
	if v := al[1].(map[string]any)["value"].(string); !strings.HasPrefix(v, "host-") {
		t.Errorf("host-алиас → host-…: %q", v)
	}
	for i := 2; i < 4; i++ {
		if v := al[i].(map[string]any)["value"].(string); !strings.HasPrefix(v, "subj-") {
			t.Errorf("алиас %d → subj-…: %q", i, v)
		}
	}
	nodes := doc["summary"].(map[string]any)["nodes"].([]any)
	if !strings.HasPrefix(nodes[0].(string), "host-") || !strings.HasPrefix(nodes[1].(map[string]any)["node"].(string), "host-") || nodes[2] != 7 {
		t.Errorf("summary.nodes: %v", nodes)
	}
	fv := doc["facets"].([]any)[0].(map[string]any)["values"].([]any)
	if !strings.HasPrefix(fv[0].(map[string]any)["value"].(string), "subj-") {
		t.Errorf("фасет субъектов: %v", fv)
	}
}
