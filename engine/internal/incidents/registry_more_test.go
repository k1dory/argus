package incidents

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

var tNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// ev — событие с временем «база + sec секунд».
func ev(sec int, actor, node string) *model.Event {
	e := &model.Event{TS: model.FormatTS(tNow.Add(time.Duration(sec) * time.Second)), Source: "sshd", SourceClass: "auth",
		Action: "login", Outcome: "failure", ActorName: actor, Node: node, Attrs: map[string]string{}}
	return e
}

// det — сработка правила по событиям; First/Last — по краям.
func det(r *rules.Rule, key string, evs ...*model.Event) eval.Detection {
	d := eval.Detection{Rule: r, Key: key, Events: evs}
	if len(evs) > 0 {
		d.First, d.Last = evs[0].Time(), evs[len(evs)-1].Time()
	}
	return d
}

func simpleRule(id, level string) *rules.Rule {
	return &rules.Rule{ID: id, Title: "Правило " + id, Level: level, Tags: []string{"test"}}
}

func TestApplyCreatesUpdatesAndSkips(t *testing.T) {
	r := simpleRule("ssh", "high")
	reg := NewRegistry(41, nil)
	created, updated, dropped := reg.Apply([]eval.Detection{det(r, "root", ev(0, "root", "h1"), ev(1, "root", "h1"))}, tNow)
	if len(created) != 1 || len(updated) != 0 || len(dropped) != 0 {
		t.Fatalf("created %d updated %d dropped %v", len(created), len(updated), dropped)
	}
	inc := created[0]
	if inc.IncidentID != "INC-42" || inc.Status != StatusNew || inc.EventCount != 2 || inc.ActorName != "root" || inc.Node != "h1" {
		t.Fatalf("%+v", inc)
	}
	if inc.CreatedAt != "2026-10-29 12:00:00" || inc.FirstTS != model.FormatTS(tNow) {
		t.Fatalf("метки времени: %+v", inc)
	}
	// Та же сработка без новых событий — ничего не пишется.
	c2, u2, _ := reg.Apply([]eval.Detection{det(r, "root", ev(0, "root", "h1"), ev(1, "root", "h1"))}, tNow.Add(time.Minute))
	if len(c2)+len(u2) != 0 {
		t.Fatalf("без новых событий записи нет: %d/%d", len(c2), len(u2))
	}
	// Новое событие — обновление того же инцидента, ПДн подхватывается.
	e3 := ev(5, "root", "h1")
	e3.PII = 1
	e3.Source = "pam"
	c3, u3, _ := reg.Apply([]eval.Detection{det(r, "root", ev(0, "root", "h1"), ev(1, "root", "h1"), e3)}, tNow.Add(2*time.Minute))
	if len(c3) != 0 || len(u3) != 1 || u3[0] != inc {
		t.Fatalf("ожидалось обновление того же инцидента: %d/%d", len(c3), len(u3))
	}
	if inc.EventCount != 3 || inc.PII != 1 || inc.UpdatedAt != "2026-10-29 12:02:00" || strings.Join(inc.Sources, ",") != "pam,sshd" {
		t.Fatalf("обновлённый инцидент: %+v", inc)
	}
	// Закрыт оператором: без новых событий новый не заводится, с новыми — заводится.
	inc.Status = StatusClosed
	c4, _, _ := reg.Apply([]eval.Detection{det(r, "root", ev(0, "root", "h1"), e3)}, tNow.Add(3*time.Minute))
	if len(c4) != 0 {
		t.Fatal("закрытый инцидент без новых событий не пересоздаётся")
	}
	c5, _, _ := reg.Apply([]eval.Detection{det(r, "root", ev(0, "root", "h1"), e3, ev(60, "root", "h1"))}, tNow.Add(3*time.Minute))
	if len(c5) != 1 || c5[0].IncidentID != "INC-43" {
		t.Fatalf("новое событие после закрытия — новый инцидент: %+v", c5)
	}
}

func TestSetMaxNewDropsPerRule(t *testing.T) {
	r1, r2 := simpleRule("a", "low"), simpleRule("b", "low")
	reg := NewRegistry(0, nil)
	reg.SetMaxNew(2)
	var dets []eval.Detection
	for i := 0; i < 5; i++ {
		dets = append(dets, det(r1, fmt.Sprintf("u%d", i), ev(i, fmt.Sprintf("u%d", i), "h")))
	}
	dets = append(dets, det(r2, "z", ev(9, "z", "h")))
	created, _, dropped := reg.Apply(dets, tNow)
	if len(created) != 2 || dropped["a"] != 3 || dropped["b"] != 1 {
		t.Fatalf("created %d dropped %v", len(created), dropped)
	}
	// Обновления существующих под предел не попадают.
	reg.SetMaxNew(1)
	_, updated, dropped := reg.Apply([]eval.Detection{det(r1, "u0", ev(0, "u0", "h"), ev(1, "u0", "h")), det(r1, "u1", ev(1, "u1", "h"), ev(2, "u1", "h"))}, tNow.Add(time.Minute))
	if len(updated) != 2 || len(dropped) != 0 {
		t.Fatalf("обновления не ограничиваются: updated %d dropped %v", len(updated), dropped)
	}
	reg.SetMaxNew(0)
	created, _, dropped = reg.Apply(dets, tNow.Add(2*time.Minute))
	if len(created) != 4 || len(dropped) != 0 {
		t.Fatalf("без предела заводятся все оставшиеся: %d %v", len(created), dropped)
	}
}

func TestBuildActorNodeStatusAndReason(t *testing.T) {
	// critical — сразу escalated; group_by src.ip — субъект = ключ, а не логин.
	r := simpleRule("scan", "critical")
	r.Detection.Threshold = &rules.Threshold{Kind: "count", Count: 3, Window: "5m", GroupBy: "src.ip"}
	e := ev(0, "admin", "fw")
	e.SrcIP, e.DstIP, e.DstPort = "203.0.113.5", "10.0.0.1", 22
	d := det(r, "203.0.113.5", e)
	d.Reason = "3 порта за 5 минут"
	inc := build(d, tNow)
	if inc.Status != StatusEscalated || inc.ActorName != "203.0.113.5" || inc.Node != "fw" {
		t.Fatalf("%+v", inc)
	}
	if last := inc.Chain[len(inc.Chain)-1]; last != "→ 3 порта за 5 минут" {
		t.Fatalf("причина в конце цепочки: %q", last)
	}
	if !strings.Contains(inc.Chain[0], "10.0.0.1:22") {
		t.Fatalf("деталь без объекта — адрес назначения: %q", inc.Chain[0])
	}
	// Ключ «-» (нет адреса) — субъект из событий; без субъекта в событиях — ключ.
	d2 := det(r, "-", ev(0, "", "fw"))
	if inc := build(d2, tNow); inc.ActorName != "-" {
		t.Fatalf("субъект по умолчанию — ключ группы: %q", inc.ActorName)
	}
	r3 := simpleRule("x", "low")
	if inc := build(det(r3, "grp", ev(0, "", "")), tNow); inc.ActorName != "grp" || inc.Node != "" {
		t.Fatalf("%+v", inc)
	}
}

func TestChainSamplingDetailsAndCut(t *testing.T) {
	var evs []*model.Event
	for i := 0; i < 30; i++ {
		e := ev(i, "u", "node")
		e.Object = fmt.Sprintf("obj-%02d", i)
		evs = append(evs, e)
	}
	got := chain(evs, 12)
	if len(got) != 12 {
		t.Fatalf("не длиннее max: %d", len(got))
	}
	if !strings.Contains(got[0], "obj-00") || !strings.Contains(got[1], "obj-02") {
		t.Fatalf("прореживание с шагом len/max: %q %q", got[0], got[1])
	}
	if !strings.HasPrefix(got[0], "12:00:00  ") {
		t.Fatalf("время — HH:MM:SS: %q", got[0])
	}

	// Числовое измерение, деталь — субъект, короткая метка времени как есть.
	m := &model.Event{TS: "short", Source: "disk", Node: "db-01", Action: "disk.usage", ActorName: "clickhouse", Value: 91.5, Unit: "percent"}
	line := chain([]*model.Event{m}, 5)[0]
	if !strings.HasPrefix(line, "short  ") || !strings.Contains(line, "clickhouse 91.5 percent") {
		t.Fatalf("%q", line)
	}

	// Кириллица режется по рунам, итог — валидный UTF-8 с многоточием.
	long := &model.Event{TS: model.FormatTS(tNow), Source: strings.Repeat("и", 20), Node: "н", Action: "a", Object: strings.Repeat("я", 70)}
	line = chain([]*model.Event{long}, 5)[0]
	if !utf8.ValidString(line) || !strings.Contains(line, strings.Repeat("и", 15)+"…") || !strings.HasSuffix(line, strings.Repeat("я", 59)+"…") {
		t.Fatalf("%q", line)
	}
	if cut("abc", 3) != "abc" || cut("abcd", 3) != "ab…" || cut("", 1) != "" {
		t.Fatal("cut: граница ровно n символов не режется")
	}
}

func TestPruneRemovesOnlyOldFinal(t *testing.T) {
	old, fresh := "2026-10-29 10:00:00", "2026-10-29 11:59:00"
	reg := NewRegistry(0, []Incident{
		{IncidentID: "INC-1", RuleID: "a", Status: StatusClosed, ActorName: "1", UpdatedAt: old},
		{IncidentID: "INC-2", RuleID: "a", Status: StatusFalsePositive, ActorName: "2", UpdatedAt: fresh},
		{IncidentID: "INC-3", RuleID: "a", Status: StatusNew, ActorName: "3", UpdatedAt: old},
		{IncidentID: "INC-4", RuleID: "abs", Status: StatusClosed, ActorName: "4", UpdatedAt: old},
		{IncidentID: "INC-5", RuleID: "a", Status: StatusClosed, ActorName: "5"}, // без updated_at — чистится
	})
	n := reg.Prune(tNow, time.Hour, func(rule string) bool { return rule == "abs" })
	if n != 2 || len(reg.open) != 3 {
		t.Fatalf("удалено %d, осталось %d", n, len(reg.open))
	}
	for _, k := range []string{"a|2|", "a|3|", "abs|4|"} {
		if _, ok := reg.open[k]; !ok {
			t.Fatalf("%s должен остаться", k)
		}
	}
	// Через два часа устарел и свежий, без keep чистится и absence; открытый остаётся.
	if n := reg.Prune(tNow.Add(2*time.Hour), time.Hour, nil); n != 2 || len(reg.open) != 1 {
		t.Fatalf("без keep чистится и absence: %d, осталось %d", n, len(reg.open))
	}
}

func TestAddSystemOpenByRuleAndNextID(t *testing.T) {
	reg := NewRegistry(7, []Incident{{IncidentID: "INC-3", RuleID: "storm", ActorName: "src-a", Status: StatusClosed}})
	if reg.OpenByRule("storm") != nil || reg.OpenByRuleActor("storm", "src-a") != nil {
		t.Fatal("закрытые не считаются открытыми")
	}
	id, err := reg.NextID()
	if err != nil || id != "INC-8" {
		t.Fatalf("%s %v", id, err)
	}
	sys := &Incident{IncidentID: id, RuleID: "storm", ActorName: "src-b", Node: "argus-engine", Status: StatusNew}
	reg.AddSystem(sys)
	if reg.OpenByRule("storm") != sys || reg.OpenByRuleActor("storm", "src-b") != sys {
		t.Fatal("системный инцидент должен находиться по правилу и субъекту")
	}
	if reg.OpenByRuleActor("storm", "src-a") != nil || reg.OpenByRule("other") != nil {
		t.Fatal("чужой субъект / правило — nil")
	}
	if id2, _ := reg.NextID(); id2 != "INC-9" {
		t.Fatalf("номера идут подряд: %s", id2)
	}
	// Apply после NextID продолжает ту же нумерацию.
	created, _, _ := reg.Apply([]eval.Detection{det(simpleRule("x", "low"), "k", ev(0, "k", ""))}, tNow)
	if created[0].IncidentID != "INC-10" {
		t.Fatalf("%s", created[0].IncidentID)
	}
}

func TestSummary(t *testing.T) {
	inc := &Incident{IncidentID: "INC-5", Level: "high", RuleTitle: "Подбор пароля SSH", ActorName: "203.0.113.5", EventCount: 17}
	if got := inc.Summary(); got != "INC-5 · HIGH · Подбор пароля SSH · 203.0.113.5 · 17 событий" {
		t.Fatalf("%q", got)
	}
}

func TestReconcileRemainingBranches(t *testing.T) {
	reg := NewRegistry(0, nil)
	// Эскалация тишиной не перебивает статус оператора (не new, не final).
	esc := &Incident{IncidentID: "INC-1", Status: StatusEscalated, Note: "эскалирован", UpdatedAt: "2026-10-29 12:00:00"}
	// Закрытие движком: заметка оператора уже содержится — не дублируется; updated_at оператора позже нашего — сдвиг.
	cl := &Incident{IncidentID: "INC-2", Status: StatusClosed, Note: "смотрю\nзакрыт автоматикой", UpdatedAt: "2026-10-29 12:00:00"}
	// Пустая заметка оператора — наша остаётся как есть.
	cl2 := &Incident{IncidentID: "INC-3", Status: StatusClosed, Note: "закрыт автоматикой", UpdatedAt: "2026-10-29 12:00:00"}
	ops := map[string]Operator{
		"INC-1": {Status: StatusObserving, Owner: "op", UpdatedAt: "2026-10-29 11:00:00"},
		"INC-2": {Status: StatusInProgress, Owner: "op", Note: "смотрю", UpdatedAt: "2026-10-29 12:00:30"},
		"INC-3": {Status: StatusInProgress, Owner: "op2", UpdatedAt: "2026-10-29 11:00:00"},
	}
	out := reg.Reconcile([]*Incident{esc, cl, cl2}, ops, map[string]bool{"INC-1": true, "INC-2": true, "INC-3": true}, tNow)
	if len(out) != 2 || out[0] != cl || out[1] != cl2 {
		t.Fatalf("эскалация поверх статуса оператора не пишется: %d", len(out))
	}
	if esc.Status != StatusObserving || esc.Owner != "op" {
		t.Fatalf("%+v", esc)
	}
	if cl.Note != "смотрю\nзакрыт автоматикой" || cl.UpdatedAt != "2026-10-29 12:00:31" || cl.Owner != "op" {
		t.Fatalf("%+v", cl)
	}
	if cl2.Note != "закрыт автоматикой" || cl2.Owner != "op2" || cl2.UpdatedAt != "2026-10-29 12:00:00" {
		t.Fatalf("%+v", cl2)
	}
}

// Событие утечки без разборчивого времени: секрет всё равно требует ротации.
func TestNoteSecretsEventWithoutTime(t *testing.T) {
	r := secretEchoRule(t)
	e := ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa")
	e.TS = "нет времени"
	inc := &Incident{}
	inc.noteSecrets(det(r, "project_7_bot", e))
	if len(inc.closeNeed) != 1 {
		t.Fatalf("секрет должен быть учтён: %+v", inc.closeNeed)
	}
	for _, ts := range inc.closeNeed {
		if !ts.IsZero() {
			t.Fatal("время утечки неизвестно — нулевое")
		}
	}
	if inc.allRotated() {
		t.Fatal("без ротации не закрывается")
	}
	if (&Incident{}).allRotated() {
		t.Fatal("без секретов allRotated — false")
	}
	// Правило без close_match секреты не ведёт; событие без ключа — unmatchable.
	plain := &Incident{}
	plain.noteSecrets(det(simpleRule("p", "low"), "k", e))
	if plain.closeNeed != nil {
		t.Fatal("правило без close_match")
	}
	um := &Incident{}
	um.noteSecrets(det(r, "k", ciEvent(2, "gitlab.build.success", "group/project-A", "", "TOKEN=glpat-bbbbbbbbbbbb")))
	if !um.unmatchable {
		t.Fatal("событие без secret_id — unmatchable")
	}
}

func TestCloseMatchedEventWithoutKey(t *testing.T) {
	reg, r, _ := leak(t, ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa"))
	closed, review := reg.CloseMatched(r.ID, ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "", ""), r, "ротация", tNow)
	if closed != nil || review != nil {
		t.Fatal("событие без ключа close_match ничего не закрывает")
	}
}

// Неразборчивый updated_at оператора лексически «позже» нашего: сдвиг
// невозможен, наша метка остаётся, строка всё равно пишется.
func TestReconcileUnparsableOperatorStamp(t *testing.T) {
	reg := NewRegistry(0, nil)
	inc := &Incident{IncidentID: "INC-1", Status: StatusNew, UpdatedAt: "2026-10-29 12:00:00"}
	ops := map[string]Operator{"INC-1": {Status: StatusObserving, Owner: "op", UpdatedAt: "zzz"}}
	out := reg.Reconcile([]*Incident{inc}, ops, nil, tNow)
	if len(out) != 1 || inc.UpdatedAt != "2026-10-29 12:00:00" || inc.Status != StatusObserving {
		t.Fatalf("%d %+v", len(out), inc)
	}
}
