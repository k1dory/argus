package main

import (
	"regexp"
	"strings"
	"testing"
)

const actorResolvedBody = `{"alias":"ipetrov","at":"2026-10-24T10:00:00Z","status":"resolved","matches":[
 {"person_id":"i.petrov","display":"Иван Петров","kind":"person","alias_kind":"login","valid_from":"1970-01-01T00:00:00Z","valid_to":null}]}`

// actorBody — паспорт i.petrov: учётки в алиасах, узлы в сводке, строка
// таймлайна с ПДн и секретом в attrs, лишняя колонка.
const actorBody = `{"person":{"person_id":"i.petrov","display":"Иван Петров","kind":"person","team":"platform","note":"тел. ` + piiPhone + `"},
 "aliases":[{"kind":"email","value":"i.petrov@example.org","valid_from":"1970-01-01T00:00:00Z","valid_to":null,"source":"yaml","confidence":1},
            {"kind":"login","value":"ipetrov","valid_from":"1970-01-01T00:00:00Z","valid_to":null,"source":"event:idp.example","confidence":1},
            {"kind":"ip","value":"10.77.0.42","valid_from":"2026-10-15T09:00:00Z","valid_to":null,"source":"event:vpn.example","confidence":1},
            {"kind":"host","value":"ws-petrov","valid_from":"1970-01-01T00:00:00Z","valid_to":"2026-10-01T00:00:00Z","source":"api","confidence":0.9}],
 "range":{"from":"2026-10-17T10:00:00Z","to":"2026-10-24T10:00:00Z","key":"7d"},
 "summary":{"events":12,"by_source_class":{"identity":4,"syslog":6,"netflow":2},
   "nodes":[{"node":"web-01","count":5,"first_ts":"2026-10-18 20:00:00","last_ts":"2026-10-18 20:01:00"},{"node":"db-01","count":2},{"node":"ws-petrov","count":1}],
   "src_ips":[{"src_ip":"10.77.0.11","count":3},{"src_ip":"10.77.0.42","count":4}],"incidents":1},
 "ambiguous":[{"kind":"ip","value":"10.77.0.42"},{"kind":"login","value":"ipetrov"}],
 "sources":[{"source":"idp.example","source_class":"identity","count":4,"first_ts":"2026-10-16 09:00:00","last_ts":"2026-10-16 09:01:30"}],
 "missing":["incidents"],"limit":100,"generated_at":"2026-10-24T10:00:01Z",
 "logins":[{"ts":"2026-10-16 09:00:00","source":"idp.example","source_class":"identity","action":"auth.login","outcome":"failure","actor_name":"ipetrov","src_ip":"203.0.113.9","count":1}],
 "hosts":[{"node":"db-01","session_id":"s-1501","first":"2026-10-15 09:35:00","last":"2026-10-15 09:36:00","count":2}],
 "network":[{"src_ip":"10.77.0.42","dst_ip":"10.20.5.7","dst_port":5432,"count":1,"bytes":640000}],
 "apps":[{"object":"grafana","action":"app.authorize","count":1}],
 "changes":[{"ts":"2026-10-18 20:01:00","action":"config.update","object":"/etc/nginx/conf.d/api.conf","node":"web-01","outcome":"success"}],
 "incidents":[{"id":"INC-7","level":"high","status":"new","rule_id":"a41c-cicd-007","rule_title":"CI job echoed a secret","created_at":"2026-10-18T20:05:00Z"}],
 "timeline":[{"ts":"2026-10-18 20:01:00","source":"syslog.web-01","source_class":"syslog","action":"config.update","outcome":"success","severity":3,"level":"low",
   "actor_name":"ipetrov","actor_kind":"user","object":"/etc/nginx/conf.d/api.conf","node":"web-01","session_id":"s-1801","src_ip":"","dst_ip":"","value":0,"unit":"",
   "attrs":{"log":"PASSWORD=` + canary + `"},"pii":0,"internal_column":"x"},
  {"ts":"2026-10-18 19:00:00","source":"crm","source_class":"app","action":"crm.export","outcome":"success","severity":3,"level":"low","actor_name":"ipetrov",
   "object":"Иванов Иван Иванович, паспорт 4510 123456","node":"crm-01","pii":1,"attrs":{"client":"Иванов И.И."}}]}`

func TestGetActorFullByAlias(t *testing.T) {
	s := newSession(t, profileFull)
	out, isErr := s.call("get_actor", map[string]any{"alias": "ipetrov"})
	if isErr {
		t.Fatal(out)
	}
	q := s.con.query()
	if q.Get("range") != "7d" || q.Get("limit") != "100" {
		t.Errorf("параметры паспорта по умолчанию: %v", q)
	}
	for _, want := range []string{`"person_id":"i.petrov"`, "Иван Петров", `"value":"10.77.0.42"`, `"node":"ws-petrov"`, `"ambiguous"`, `"sources"`, `"missing":["incidents"]`, "INC-7", `"timeline"`, `"internal_column":"x"`} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
	assertNoLeak(t, "full", out, canary) // секреты режутся и в full
	if !strings.HasPrefix(out, untrustedNotice) {
		t.Error("предупреждение о недоверенном вводе")
	}
	out, isErr = s.call("get_actor", map[string]any{"person_id": "i.petrov", "range": "30d", "limit": 9000})
	if isErr || !strings.Contains(out, `"team":"platform"`) {
		t.Fatalf("по person_id: %v %s", isErr, out)
	}
	if q := s.con.query(); q.Get("range") != "30d" || q.Get("limit") != "500" {
		t.Errorf("range/limit не переданы или лимит не ограничен: %v", q)
	}
}

func TestGetActorUnboundAndAmbiguousAreAnswers(t *testing.T) {
	s := newSession(t, profileFull)
	out, isErr := s.call("get_actor", map[string]any{"alias": "nobody"})
	if isErr || !strings.Contains(out, `"status":"unbound"`) || strings.Contains(out, `"person":`) {
		t.Fatalf("unbound — ответ резолва, не ошибка и не паспорт: %v %s", isErr, out)
	}
	if q := s.con.query(); q.Get("alias") != "nobody" || !strings.Contains(q.Get("at"), "T") {
		t.Errorf("резолв: alias и at (RFC3339) обязательны: %v", q)
	}
	out, isErr = s.call("get_actor", map[string]any{"alias": "10.77.0.99"})
	if isErr || !strings.Contains(out, `"status":"ambiguous"`) || !strings.Contains(out, "a.sidorov") || strings.Contains(out, `"timeline"`) {
		t.Fatalf("ambiguous — обе персоны, паспорт не запрашивается: %v %s", isErr, out)
	}
}

func TestGetActorValidation(t *testing.T) {
	s := newSession(t, profileFull)
	for name, args := range map[string]map[string]any{
		"пусто":        {},
		"оба":          {"alias": "ipetrov", "person_id": "i.petrov"},
		"плохой range": {"alias": "ipetrov", "range": "1y"},
	} {
		if out, isErr := s.call("get_actor", args); !isErr {
			t.Errorf("%s: ожидалась ошибка, получено %s", name, out)
		}
	}
	if q := s.con.query(); len(q) != 0 {
		t.Errorf("отказы — до запроса в консоль, а ушло %v", q)
	}
	if out, isErr := s.call("get_actor", map[string]any{"person_id": "unknown"}); !isErr || !strings.Contains(out, "404") {
		t.Errorf("404 консоли — ошибка инструмента: %v %s", isErr, out)
	}
}

var subjRe = regexp.MustCompile(`subj-[0-9a-f]{10}`)

// В triage: сырой логин не принимается; псевдоним из ответов MCP разрешается в
// консоль, а паспорт уходит модели без учёток, имён и ПДн.
func TestGetActorTriage(t *testing.T) {
	s := newSession(t, profileTriage, "Петров")
	for name, args := range map[string]map[string]any{
		"сырой логин":           {"alias": "ipetrov"},
		"сырой адрес":           {"alias": "10.77.0.42"},
		"сырой person_id":       {"person_id": "i.petrov"},
		"неизвестный псевдоним": {"alias": "subj-0000000000"},
	} {
		if out, isErr := s.call("get_actor", args); !isErr || !strings.Contains(out, "псевдоним") {
			t.Errorf("%s: ожидался отказ triage, получено %v %s", name, isErr, out)
		}
	}
	if q := s.con.query(); len(q) != 0 {
		t.Fatalf("отказы — до запроса в консоль, а ушло %v", q)
	}
	// Псевдоним субъекта из карточки инцидента (project_7_bot) → резолв → паспорт.
	card, _ := s.call("get_incident", map[string]any{"id": "INC-7"})
	i := strings.Index(card, `"actor_name":"subj-`)
	if i < 0 {
		t.Fatalf("нет псевдонима:\n%s", card)
	}
	p := card[i+len(`"actor_name":"`) : i+len(`"actor_name":"`)+15]
	out, isErr := s.call("get_actor", map[string]any{"alias": p})
	if isErr {
		t.Fatal(out)
	}
	if q := s.con.query(); q.Get("range") != "7d" {
		t.Errorf("паспорт не запрошен: %v", q)
	}
	assertNoLeak(t, "triage get_actor", out, "i.petrov", "ipetrov", "Петров", "Иван", piiPhone, canary, "ws-petrov",
		`"internal_column"`, "Иванов", "4510 123456", "project_7_bot")
	for _, want := range []string{`"value":"10.77.0.42"`, `"ambiguous":[{"kind":"ip","value":"10.77.0.42"},{"kind":"login","value":"subj-`, `"source":"idp.example"`, `"missing":["incidents"]`, `"key":"7d"`, "web-01", "db-01", "INC-7", `"team":"platform"`, piiMasked, "203.0.113.9"} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q:\n%s", want, out)
		}
	}
	if n := len(subjRe.FindAllString(out, -1)); n < 3 {
		t.Errorf("учётки и person_id должны стать псевдонимами, найдено %d:\n%s", n, out)
	}
	// person_id-псевдоним из паспорта работает как вход.
	person := out[strings.Index(out, `"person":`):]
	pid := subjRe.FindString(person[strings.Index(person, `"person_id":`):])
	out2, isErr := s.call("get_actor", map[string]any{"person_id": pid})
	if isErr || !strings.Contains(out2, `"team":"platform"`) {
		t.Fatalf("паспорт по псевдониму person_id: %v %s", isErr, out2)
	}
	assertNoLeak(t, "triage by person_id", out2, "i.petrov", "ipetrov", "Петров")
	// Резолв unbound в triage — тоже ответ, без эха сырого значения.
	rs, _ := s.call("search_events", map[string]any{"source": "gitlab.ci"})
	alias := subjRe.FindString(rs)
	out3, isErr := s.call("get_actor", map[string]any{"alias": alias})
	if isErr || !strings.Contains(out3, `"status":"unbound"`) {
		t.Fatalf("unbound в triage: %v %s", isErr, out3)
	}
	assertNoLeak(t, "unbound echo", out3, piiSubject, "synthetic.person")
}

func TestSearchSyntaxMentionsActor(t *testing.T) {
	if !strings.Contains(searchSyntax+actorSyntax, "get_actor") || !strings.Contains(actorSyntax, "ambiguous") {
		t.Error("ресурс argus://search-syntax должен описывать get_actor и статусы резолва")
	}
}
