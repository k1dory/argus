package identity

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

const policyYAML = `
persons:
  i.petrov:
    aliases:
      - {kind: login, value: ipetrov}
policies:
  ip:    { sources: ["event:vpn.*"], max_open: 2, churn: { max: 20, window: 24h }, on_violation: flag }
  host:  { sources: ["mdm.*"], max_open: 1, churn: { max: 1, window: 30d }, on_violation: hold }
  email: { sources: [], churn: { max: 1, window: 90d }, on_violation: reject }
  login: { max_open: 3 }
`

func TestParsePolicies(t *testing.T) {
	set, err := Parse([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Policies) != 4 || len(set.Aliases) != 1 {
		t.Fatalf("policies %d aliases %d", len(set.Policies), len(set.Aliases))
	}
	ip := set.Policies["ip"]
	if ip.Kind != "ip" || len(ip.Sources) != 1 || ip.Sources[0] != "event:vpn.*" || ip.MaxOpen != 2 || ip.ChurnMax != 20 ||
		ip.ChurnWindow != 24*time.Hour || ip.ChurnRaw != "24h" || ip.OnViolation != ActionFlag {
		t.Errorf("ip: %+v", ip)
	}
	host := set.Policies["host"]
	if host.Sources[0] != "event:mdm.*" || host.ChurnWindow != 30*24*time.Hour || host.OnViolation != ActionHold {
		t.Errorf("host: глоб без префикса получает event:, окно в сутках: %+v", host)
	}
	email := set.Policies["email"]
	if email.Sources == nil || len(email.Sources) != 0 || email.OnViolation != ActionReject {
		t.Errorf("email: пустой список источников — не nil: %+v", email)
	}
	login := set.Policies["login"]
	if login.Sources != nil || login.MaxOpen != 3 || login.ChurnMax != 0 || login.OnViolation != ActionFlag {
		t.Errorf("login: без sources — nil, on_violation по умолчанию flag: %+v", login)
	}
	// Файл без policies — нет политик.
	set, err = Parse([]byte("persons:\n  a:\n    aliases: []\n"))
	if err != nil || set.Policies != nil {
		t.Errorf("без policies: %+v %v", set.Policies, err)
	}
}

func TestParsePoliciesErrors(t *testing.T) {
	cases := map[string]string{
		"policies:\n  passport: { max_open: 1 }\n":                            "policies.passport",
		"policies:\n  ip: { churn: { max: 1, window: fortnight } }\n":         "policies.ip.churn.window",
		"policies:\n  ip: { churn: { max: 1, window: 0h } }\n":                "policies.ip.churn.window",
		"policies:\n  ip: { churn: { max: 0, window: 1h } }\n":                "policies.ip.churn.max",
		"policies:\n  ip: { max_open: 1, on_violation: drop }\n":              "policies.ip.on_violation",
		"policies:\n  ip: { max_open: -1 }\n":                                 "policies.ip.max_open",
		"policies:\n  ip: { on_violation: flag }\n":                           "без ограничений",
		"policies:\n  ip: { sources: [\"vpn.[\"] }\n":                         "policies.ip.sources[0]",
		"policies:\n  ip: { sources: [\"\"] }\n":                              "policies.ip.sources[0]",
		"policies:\n  ip: { max_open: 1, colour: red }\n":                     "colour",
		"policies:\n  ip: { churn: { max: 1, window: 1h, burst: 2 } }\n":      "burst",
		"persons:\n  a:\n    aliases: []\npolicies:\n  ip: { max_open: x }\n": "into int",
	}
	for yml, want := range cases {
		_, err := Parse([]byte(yml))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: ожидалась ошибка с %q, получено %v", yml, want, err)
		}
	}
	for _, s := range []string{"24h", "30d", "2w", "90m"} {
		if _, err := ParseWindow(s); err != nil {
			t.Errorf("окно %q: %v", s, err)
		}
	}
	if d, _ := ParseWindow("2w"); d != 14*24*time.Hour {
		t.Errorf("2w = %v", d)
	}
}

func mustPolicies(t *testing.T, yml string) Policies {
	t.Helper()
	set, err := Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	return set.Policies
}

func at(s string) time.Time {
	t, err := ParseTime(s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestEvaluateSources(t *testing.T) {
	ps := mustPolicies(t, policyYAML)
	a := Alias{PersonID: "i.petrov", Kind: KindIP, Value: "10.77.0.11", ValidFrom: at("2026-10-20"), Source: "event:vpn.example", Confidence: 1}
	if d := ps.Evaluate(a, nil); d.Rule != "" {
		t.Errorf("vpn.example разрешён глобом vpn.*: %+v", d)
	}
	a.Source = "event:idp.example"
	d := ps.Evaluate(a, nil)
	if d.Rule != RuleSources || d.Action != ActionFlag || d.Count != 1 || d.Limit != 0 || d.Window != "" {
		t.Errorf("idp.example не в sources: %+v", d)
	}
	// Пустой список — любой источник событий запрещён.
	e := Alias{PersonID: "i.petrov", Kind: KindEmail, Value: "x@example.org", ValidFrom: at("2026-10-20"), Source: "event:idp.example"}
	if d := ps.Evaluate(e, nil); d.Rule != RuleSources || d.Action != ActionReject {
		t.Errorf("email из события при sources: []: %+v", d)
	}
	// yaml и api политиками не проверяются.
	for _, src := range []string{SourceYAML, SourceAPI} {
		e.Source = src
		if d := ps.Evaluate(e, nil); d.Rule != "" {
			t.Errorf("источник %s должен проходить без проверки: %+v", src, d)
		}
	}
	// Вид без политики и без sources — не ограничен.
	u := Alias{PersonID: "i.petrov", Kind: KindUID, Value: "1", ValidFrom: at("2026-10-20"), Source: "event:anything"}
	if d := ps.Evaluate(u, nil); d.Rule != "" {
		t.Errorf("uid без политики: %+v", d)
	}
	l := Alias{PersonID: "i.petrov", Kind: KindLogin, Value: "x", ValidFrom: at("2026-10-20"), Source: "event:anything"}
	if d := ps.Evaluate(l, nil); d.Rule != "" {
		t.Errorf("login без sources — любой источник: %+v", d)
	}
}

func TestEvaluateMaxOpen(t *testing.T) {
	ps := mustPolicies(t, policyYAML)
	to := at("2026-10-10")
	state := []Alias{
		{PersonID: "i.petrov", Kind: KindIP, Value: "10.77.0.1", ValidFrom: at("2026-10-01"), Source: "event:vpn.example"},
		{PersonID: "i.petrov", Kind: KindIP, Value: "10.77.0.2", ValidFrom: at("2026-10-02"), Source: "event:vpn.example"},
		{PersonID: "i.petrov", Kind: KindIP, Value: "10.77.0.3", ValidFrom: at("2026-10-03"), ValidTo: &to, Source: "yaml"}, // закрыт — не считается
		{PersonID: "a.sidorov", Kind: KindIP, Value: "10.77.0.4", ValidFrom: at("2026-10-03"), Source: "event:vpn.example"}, // чужой
		{PersonID: "i.petrov", Kind: KindHost, Value: "ws-1", ValidFrom: at("2026-10-03"), Source: "event:mdm.example"},     // другой вид
	}
	in := Alias{PersonID: "i.petrov", Kind: KindIP, Value: "10.77.0.9", ValidFrom: at("2026-10-20"), Source: "event:vpn.example"}
	d := ps.Evaluate(in, state)
	if d.Rule != RuleMaxOpen || d.Limit != 2 || d.Count != 3 || d.Action != ActionFlag {
		t.Errorf("третий открытый при max_open 2: %+v", d)
	}
	// Входящий с valid_to — открытых не прибавляет.
	closed := in
	closed.ValidTo = &to
	closed.ValidFrom = at("2026-10-05")
	if d := ps.Evaluate(closed, state); d.Rule != "" {
		t.Errorf("закрытый интервал не считается открытым: %+v", d)
	}
	// Повтор снимка уже известного алиаса — не нарушение.
	if d := ps.Evaluate(state[1], state); d.Rule != "" {
		t.Errorf("повтор снимка: %+v", d)
	}
	// Открытые считаются и в yaml-алиасах: ограничение — на персону.
	state[2].ValidTo = nil
	if d := ps.Evaluate(in, state[:3]); d.Rule != RuleMaxOpen || d.Count != 4 {
		t.Errorf("открытый yaml-алиас входит в счёт: %+v", d)
	}
}

func TestEvaluateChurnWindow(t *testing.T) {
	ps := mustPolicies(t, policyYAML) // host: churn max 1 / 30d, hold
	in := Alias{PersonID: "i.petrov", Kind: KindHost, Value: "ws-new", ValidFrom: at("2026-10-31 12:00:00"), Source: "event:mdm.example"}
	closed := at("2026-10-02")
	prev := Alias{PersonID: "i.petrov", Kind: KindHost, Value: "ws-old", ValidFrom: at("2026-10-01 12:00:00"), ValidTo: &closed, Source: "event:mdm.example"}
	// Ровно на границе окна (30 суток назад) — вне окна: один интервал, предел 1.
	if d := ps.Evaluate(in, []Alias{prev}); d.Rule != "" {
		t.Errorf("интервал ровно на границе окна не считается: %+v", d)
	}
	// На секунду внутри окна — второй интервал за 30d.
	prev.ValidFrom = prev.ValidFrom.Add(time.Second)
	d := ps.Evaluate(in, []Alias{prev})
	if d.Rule != RuleChurn || d.Action != ActionHold || d.Limit != 1 || d.Count != 2 || d.Window != "30d" {
		t.Errorf("второй интервал в окне: %+v", d)
	}
	// Интервалы после входящего (события не по порядку) в окно не входят.
	later := Alias{PersonID: "i.petrov", Kind: KindHost, Value: "ws-later", ValidFrom: at("2026-11-01"), Source: "event:mdm.example"}
	if d := ps.Evaluate(in, []Alias{later}); d.Rule != RuleMaxOpen {
		t.Errorf("более поздний открытый интервал — это max_open, не churn: %+v", d)
	}
	// Закрытые интервалы в окне считаются: churn — про смену устройств, не про открытые.
	laterClosed := later
	laterClosed.ValidFrom = at("2026-10-20")
	laterClosed.ValidTo = &in.ValidFrom
	if d := ps.Evaluate(in, []Alias{laterClosed}); d.Rule != RuleChurn {
		t.Errorf("закрытый интервал в окне считается: %+v", d)
	}
}

func TestDecisionApply(t *testing.T) {
	a := Alias{PersonID: "i.petrov", Kind: KindHost, Value: "ws-1", Confidence: 1, Note: "ноутбук"}
	if out, ok := (Decision{}).Apply(a); !ok || out != a {
		t.Errorf("без нарушения — как есть: %+v %v", out, ok)
	}
	out, ok := (Decision{Rule: RuleChurn, Action: ActionFlag}).Apply(a)
	if !ok || out.Note != "policy:churn; ноутбук" || out.Confidence != 1 {
		t.Errorf("flag: %+v", out)
	}
	out, ok = (Decision{Rule: RuleChurn, Action: ActionHold}).Apply(Alias{Confidence: 1})
	if !ok || out.Note != "policy:hold:churn" || out.Confidence != HoldConfidence {
		t.Errorf("hold: %+v", out)
	}
	if _, ok := (Decision{Rule: RuleSources, Action: ActionReject}).Apply(a); ok {
		t.Error("reject: записывать нечего")
	}
	// Повторное решение не дублирует префикс.
	again, _ := (Decision{Rule: RuleChurn, Action: ActionFlag}).Apply(Alias{Note: "policy:churn; ноутбук"})
	if again.Note != "policy:churn; ноутбук" {
		t.Errorf("префикс продублирован: %q", again.Note)
	}
}

// Observe с политиками: flag пишется с пометкой, hold — с confidence 0.3,
// reject — не пишется; на каждое нарушение — событие identity.policy.violation
// в журнале и счётчик в метриках. Состояние учитывает ожидающие записи того же батча.
func TestObservePolicies(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	set, err := Parse([]byte(policyYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SyncFile(ctx, set); err != nil {
		t.Fatal(err)
	}
	if len(o.Policies()) != 4 {
		t.Fatalf("политики не применены: %+v", o.Policies())
	}
	batch := []*model.Event{
		ev("2026-10-20 10:00:00.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.1"}),
		ev("2026-10-20 10:00:01.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.2"}),
		ev("2026-10-20 10:00:02.000", ActionAlias, "i.petrov", "vpn.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.3", "note": "третий"}), // max_open 2 → flag
		ev("2026-10-20 10:00:03.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "ip", "alias_value": "10.77.0.4"}),                   // не vpn.* → flag (sources)
		ev("2026-10-20 10:00:04.000", ActionAlias, "i.petrov", "mdm.example", map[string]string{"alias_kind": "host", "alias_value": "ws-1"}),
		ev("2026-10-20 10:00:05.000", ActionAlias, "i.petrov", "mdm.example", map[string]string{"alias_kind": "host", "alias_value": "ws-2"}),           // max_open 1 → hold
		ev("2026-10-20 10:00:06.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "email", "alias_value": "i@example.org"}), // sources: [] → reject
		ev("2026-10-20 10:00:07.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "uid", "alias_value": "1001"}),            // без политики
	}
	s := o.Observe(ctx, batch)
	if s.OK != 7 || s.Invalid != 0 || s.Errors != 0 || s.Policy != 4 || len(s.Retry) != 0 {
		t.Fatalf("stats %+v", s)
	}
	a, ok := st.alias(KindIP, "10.77.0.3", "i.petrov")
	if !ok || a.Note != "policy:max_open; третий" || a.Confidence != 1 {
		t.Errorf("flag max_open: %+v ok=%v", a, ok)
	}
	a, ok = st.alias(KindIP, "10.77.0.4", "i.petrov")
	if !ok || a.Note != "policy:sources" {
		t.Errorf("flag sources: %+v ok=%v", a, ok)
	}
	a, ok = st.alias(KindHost, "ws-1", "i.petrov")
	if !ok || a.Note != "" || a.Confidence != 1 {
		t.Errorf("первый host без нарушений: %+v", a)
	}
	a, ok = st.alias(KindHost, "ws-2", "i.petrov")
	if !ok || a.Note != "policy:hold:max_open" || a.Confidence != HoldConfidence {
		t.Errorf("hold: %+v ok=%v", a, ok)
	}
	if _, ok := st.alias(KindEmail, "i@example.org", "i.petrov"); ok {
		t.Error("reject: алиас записан")
	}
	if _, ok := st.alias(KindUID, "1001", "i.petrov"); !ok {
		t.Error("вид без политики должен записаться")
	}
	if len(st.events) != 4 {
		t.Fatalf("событий нарушений %d: %+v", len(st.events), st.events)
	}
	// Форма события нарушения.
	v := st.events[0]
	if v.TS != "2026-10-20 10:00:02.000" || v.Source != "argus.identity" || v.SourceClass != "identity" || v.Action != "identity.policy.violation" ||
		v.Outcome != "failure" || v.Severity != 6 || v.ActorName != "i.petrov" || v.Object != "ip:10.77.0.3" || v.Node != "" ||
		v.Value != 3 || v.Unit != "count" {
		t.Errorf("событие max_open: %+v", v)
	}
	wantAttrs := map[string]string{"policy": "ip", "rule": "max_open", "limit": "2", "source": "vpn.example", "action_taken": "flag"}
	for k, w := range wantAttrs {
		if v.Attrs[k] != w {
			t.Errorf("attrs.%s = %q, ожидалось %q", k, v.Attrs[k], w)
		}
	}
	if _, ok := v.Attrs["window"]; ok {
		t.Error("у max_open нет окна")
	}
	if a := st.events[1].Attrs; a["rule"] != "sources" || a["source"] != "idp.example" || a["action_taken"] != "flag" || a["limit"] != "" {
		t.Errorf("событие sources: %+v", a)
	}
	if e := st.events[2]; e.Attrs["rule"] != "max_open" || e.Attrs["policy"] != "host" || e.Attrs["action_taken"] != "hold" || e.Object != "host:ws-2" {
		t.Errorf("событие hold: %+v", e)
	}
	if e := st.events[3]; e.Attrs["rule"] != "sources" || e.Attrs["policy"] != "email" || e.Attrs["action_taken"] != "reject" || e.Value != 1 {
		t.Errorf("событие reject: %+v", e)
	}
	var b strings.Builder
	o.WriteMetrics(&b)
	for _, want := range []string{
		`argus_engine_identity_policy_total{rule="max_open",action="flag"} 1`,
		`argus_engine_identity_policy_total{rule="max_open",action="hold"} 1`,
		`argus_engine_identity_policy_total{rule="sources",action="flag"} 1`,
		`argus_engine_identity_policy_total{rule="sources",action="reject"} 1`,
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("нет метрики %s в:\n%s", want, b.String())
		}
	}
	// Повтор того же снимка — не нарушение (ключи уже известны), событий не прибавляется.
	s = o.Observe(ctx, batch[:2])
	if s.Policy != 0 || len(st.events) != 4 {
		t.Errorf("повтор снимка: %+v, событий %d", s, len(st.events))
	}
	// Churn через хранилище: третий host за 30 суток при max 1 → hold.
	s = o.Observe(ctx, []*model.Event{
		ev("2026-10-25 10:00:00.000", ActionRevoke, "i.petrov", "mdm.example", map[string]string{"alias_kind": "host", "alias_value": "ws-1"}),
		ev("2026-10-25 10:00:01.000", ActionRevoke, "i.petrov", "mdm.example", map[string]string{"alias_kind": "host", "alias_value": "ws-2"}),
		ev("2026-10-25 10:00:02.000", ActionAlias, "i.petrov", "mdm.example", map[string]string{"alias_kind": "host", "alias_value": "ws-3"}),
	})
	if s.OK != 3 || s.Policy != 1 {
		t.Fatalf("churn: %+v", s)
	}
	last := st.events[len(st.events)-1]
	if last.Attrs["rule"] != "churn" || last.Attrs["limit"] != "1" || last.Attrs["window"] != "30d" || last.Value != 3 || last.Attrs["action_taken"] != "hold" {
		t.Errorf("событие churn: %+v", last)
	}
	// Снятие политик — ограничений нет.
	o.SetPolicies(nil)
	s = o.Observe(ctx, []*model.Event{ev("2026-10-26 10:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "email", "alias_value": "i@example.org"})})
	if s.OK != 1 || s.Policy != 0 {
		t.Errorf("без политик: %+v", s)
	}
}

// Алиасы файла политиками не проверяются, даже если нарушают их; сбой чтения
// состояния — ошибка хранилища с повтором; сбой записи событий нарушений не
// мешает записи алиасов.
func TestObservePoliciesBypassAndErrors(t *testing.T) {
	st := newFakeStore()
	o := New(st)
	ctx := context.Background()
	set, err := Parse([]byte(`
persons:
  i.petrov:
    aliases:
      - {kind: email, value: a@example.org}
      - {kind: email, value: b@example.org}
      - {kind: email, value: c@example.org}
policies:
  email: { sources: [], max_open: 1, on_violation: reject }
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SyncFile(ctx, set); err != nil {
		t.Fatal(err)
	}
	if len(st.aliases) != 3 || len(st.events) != 0 {
		t.Fatalf("файл проходит без политик: aliases %d events %d", len(st.aliases), len(st.events))
	}
	// Та же проверка для Evaluate с source api.
	if d := o.Policies().Evaluate(Alias{PersonID: "i.petrov", Kind: KindEmail, Value: "d@example.org", Source: SourceAPI}, nil); d.Rule != "" {
		t.Errorf("api проходит без политик: %+v", d)
	}
	st.fail = "AliasesByPerson"
	s := o.Observe(ctx, []*model.Event{ev("2026-10-20 10:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "email", "alias_value": "d@example.org"})})
	if s.Errors != 1 || len(s.Retry) != 1 || s.Policy != 0 {
		t.Errorf("ошибка чтения состояния: %+v", s)
	}
	st.fail = "InsertEvents"
	s = o.Observe(ctx, []*model.Event{ev("2026-10-20 10:00:00.000", ActionAlias, "i.petrov", "idp.example", map[string]string{"alias_kind": "email", "alias_value": "d@example.org"})})
	if s.Errors != 0 || s.Policy != 1 || len(s.Retry) != 0 {
		t.Errorf("сбой записи события нарушения не считается ошибкой алиасов: %+v", s)
	}
	if _, ok := st.alias(KindEmail, "d@example.org", "i.petrov"); ok {
		t.Error("reject при недоступном журнале всё равно не пишет алиас")
	}
	// Без хранилища — no-op.
	if New(nil).Policies() != nil {
		t.Error("пустой наблюдатель без политик")
	}
}
