package incidents

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Настоящее правило из репозитория: проверяем его конфигурацию, а не копию.
func secretEchoRule(t *testing.T) *rules.Rule {
	t.Helper()
	r, err := rules.LoadFile("../../../rules/ci-secret-echo.yml")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.CloseMatch) == 0 || !r.AutoCloseEscalates() {
		t.Fatalf("ci-secret-echo: нужны close_match и auto_close_action: escalate: %+v", r)
	}
	return r
}

// ciEvent — событие CI/CD GitLab. Секрет связан с токеном: token_id (из
// имени, без регистра) и экземпляр gitlab.corp — как будто источник утечки
// знает id токена (лог CI его не знает; такие случаи — unlinked).
// Действия *_token_* приходят из аудита (source gitlab.audit). Исход —
// явно success: отзыв засчитывается только успешный.
func ciEvent(sec int, action, project, secretID, log string) *model.Event {
	e := &model.Event{TS: fmt.Sprintf("2026-08-14 04:%02d:00.000", sec), Source: "gitlab", SourceClass: "cicd",
		Outcome: "success", Vendor: "GitLab", Product: "gitlab", ActorName: "project_7_bot", Action: action, Object: project, Attrs: map[string]string{}}
	if strings.Contains(action, "_token_") {
		e.Source = "gitlab.audit"
	}
	if secretID != "" {
		e.Attrs["secret_id"] = secretID
		e.Attrs["token_id"] = "id-" + strings.ToLower(secretID)
		e.Attrs["instance"] = "gitlab.corp"
	}
	if log != "" {
		e.Attrs["log"] = log
	}
	e.Ensure()
	return e
}

// leak заводит инцидент утечки и возвращает реестр и правило.
func leak(t *testing.T, evs ...*model.Event) (*Registry, *rules.Rule, *Incident) {
	t.Helper()
	r := secretEchoRule(t)
	dets, _ := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: evs})
	reg := NewRegistry(0, nil)
	created, _, _ := reg.Apply(dets, time.Date(2026, 8, 14, 4, 30, 0, 0, time.UTC))
	if len(created) != 1 {
		t.Fatalf("ожидался один инцидент утечки: %d", len(created))
	}
	return reg, r, created[0]
}

// unlinked — событие утечки без связи с токеном (лог CI: только имя).
func unlinked(e *model.Event) *model.Event {
	delete(e.Attrs, "token_id")
	delete(e.Attrs, "instance")
	return e
}

// rotate прогоняет события ротации через правило и закрывает, как движок.
func rotate(reg *Registry, r *rules.Rule, evs ...*model.Event) *Incident {
	got, _ := rotateReview(reg, r, evs...)
	return got
}

// rotateReview — rotate, который возвращает и закрытый, и помеченный
// «нужна проверка» инцидент.
func rotateReview(reg *Registry, r *rules.Rule, evs ...*model.Event) (closed, review *Incident) {
	_, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: evs})
	for _, c := range closers {
		cl, rv := reg.CloseMatched(c.Rule.ID, c.Event, c.Rule, "ротация", time.Now())
		for _, inc := range cl {
			closed = inc
		}
		for _, inc := range rv {
			review = inc
		}
	}
	return closed, review
}

// Утечка в project-A, ротация тем же ботом, но в
// project-B и другого токена — расследование не закрывается.
func TestRotationOfOtherSecretDoesNotClose(t *testing.T) {
	reg, r, inc := leak(t, ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa"))
	if got := rotate(reg, r, ciEvent(5, "gitlab.project_access_token_revoked", "group/project-B", "tok-B", "")); got != nil {
		t.Fatalf("ротация в другом проекте закрыла %s", got.IncidentID)
	}
	if got := rotate(reg, r, ciEvent(6, "gitlab.project_access_token_revoked", "group/project-A", "tok-B", "")); got != nil {
		t.Fatal("ротация другого токена в том же проекте закрыла утечку")
	}
	if got := rotate(reg, r, ciEvent(7, "gitlab.project_access_token_revoked", "group/project-A", "", "")); got != nil {
		t.Fatal("ротация без идентификатора секрета закрыла утечку")
	}
	if inc.Status == StatusClosed {
		t.Fatal("инцидент закрыт")
	}
	if got := rotate(reg, r, ciEvent(8, "gitlab.project_access_token_revoked", "GROUP/project-A", "TOK-A", "")); got == nil || got.Status != StatusClosed {
		t.Fatal("отзыв того же токена в том же проекте закрывает утечку")
	}
}

func TestAllLeakedSecretsMustBeRotated(t *testing.T) {
	reg, r, _ := leak(t,
		ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa"),
		ciEvent(2, "gitlab.build.success", "group/project-A", "tok-C", "SECRET=cccccccccccc"))
	if rotate(reg, r, ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", "")) != nil {
		t.Fatal("утекли два секрета, отозван один — рано закрывать")
	}
	if got := rotate(reg, r, ciEvent(6, "gitlab.project_access_token_revoked", "group/project-A", "tok-C", "")); got == nil {
		t.Fatal("отозваны оба — закрыть")
	}
}

func TestLeakWithoutSecretIDNeverClosedByRotation(t *testing.T) {
	reg, r, _ := leak(t, ciEvent(1, "gitlab.build.success", "group/project-A", "", "TOKEN=glpat-aaaaaaaaaaaa"))
	if rotate(reg, r, ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", "")) != nil {
		t.Fatal("какой секрет утёк — неизвестно, ротация не доказывает устранение")
	}
}

// rules/ci-secret-echo.yml:17 закрывал утечку после 4 часов тишины. Теперь —
// эскалация один раз, инцидент остаётся открытым.
func TestSilenceEscalatesSecretLeak(t *testing.T) {
	reg, r, inc := leak(t, ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa"))
	pol := func(string) AutoClose { return AutoClose{After: r.AutoCloseAfter(), Escalate: r.AutoCloseEscalates()} }
	later := time.Date(2026, 8, 14, 10, 0, 0, 0, time.UTC)
	closed, escalated := reg.Sweep(pol, later)
	if len(closed) != 0 || len(escalated) != 1 || inc.Status != StatusEscalated {
		t.Fatalf("тишина: closed=%d escalated=%d status=%s", len(closed), len(escalated), inc.Status)
	}
	if closed, escalated = reg.Sweep(pol, later.Add(time.Hour)); len(closed)+len(escalated) != 0 {
		t.Fatal("эскалация — один раз, закрытия нет и потом")
	}
}

func TestReconcileEscalationKeepsOperatorStatus(t *testing.T) {
	reg := NewRegistry(1, nil)
	inc := &Incident{IncidentID: "INC-1", Status: StatusEscalated, UpdatedAt: "2026-08-14 10:00:00"}
	ops := map[string]Operator{"INC-1": {Status: StatusObserving, Owner: "duty", UpdatedAt: "2026-08-14 09:00:00"}}
	if out := reg.Reconcile([]*Incident{inc}, ops, map[string]bool{"INC-1": true}, time.Now()); len(out) != 0 || inc.Status != StatusObserving {
		t.Fatalf("эскалация тишиной не перебивает статус оператора: %d %s", len(out), inc.Status)
	}
	inc = &Incident{IncidentID: "INC-2", Status: StatusEscalated, UpdatedAt: "2026-08-14 10:00:00"}
	ops = map[string]Operator{"INC-2": {Status: StatusNew, UpdatedAt: "2026-08-14 09:00:00"}}
	if out := reg.Reconcile([]*Incident{inc}, ops, map[string]bool{"INC-2": true}, time.Now()); len(out) != 1 || inc.Status != StatusEscalated {
		t.Fatalf("new → escalated пишется: %d %s", len(out), inc.Status)
	}
}

func TestRestoredIncidentNotClosedByRotation(t *testing.T) {
	r := secretEchoRule(t)
	reg := NewRegistry(1, []Incident{{IncidentID: "INC-1", RuleID: r.ID, Status: StatusNew, ActorName: "project_7_bot", Node: "runner-07"}})
	if got := rotate(reg, r, ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", "")); got != nil {
		t.Fatal("после рестарта утёкшие секреты неизвестны — ротация не закрывает")
	}
}

// Секрет утёк, отозван, утёк снова (новое значение того же секрета): ротация
// другого секрета инцидента не закрывает — повторная утечка не отозвана.
func TestReleakAfterRotationNeedsNewRotation(t *testing.T) {
	r := secretEchoRule(t)
	a1 := ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa")
	b1 := ciEvent(2, "gitlab.build.success", "group/project-A", "tok-B", "SECRET=bbbbbbbbbbbb")
	reg, _, inc := leak(t, a1, b1)
	if rotate(reg, r, ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", "")) != nil {
		t.Fatal("отозван один из двух")
	}
	a2 := ciEvent(10, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-a2a2a2a2a2a2")
	dets, _ := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: []*model.Event{a1, b1, a2}})
	if _, updated, _ := reg.Apply(dets, time.Date(2026, 8, 14, 4, 40, 0, 0, time.UTC)); len(updated) != 1 || updated[0] != inc {
		t.Fatalf("повторная утечка дописывается в тот же инцидент: %d", len(updated))
	}
	if got := rotate(reg, r, ciEvent(15, "gitlab.project_access_token_revoked", "group/project-A", "tok-B", "")); got != nil {
		t.Fatal("tok-A утёк повторно после ротации — инцидент не закрывается ротацией tok-B")
	}
	if got := rotate(reg, r, ciEvent(16, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", "")); got == nil {
		t.Fatal("после повторной ротации tok-A — закрыть")
	}
}

// engineCycles ведёт себя как движок: каждый цикл — Evaluate по всему
// накопленному буферу, Apply, затем closers (старые ротации приходят снова).
type engineCycles struct {
	t      *testing.T
	r      *rules.Rule
	reg    *Registry
	buffer []*model.Event
	review []*Incident // помеченные «нужна проверка» за последний цикл
}

func (c *engineCycles) cycle(evs ...*model.Event) []*Incident {
	c.buffer = append(c.buffer, evs...)
	dets, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{c.r}, Events: append([]*model.Event(nil), c.buffer...)})
	c.reg.Apply(dets, time.Date(2026, 8, 14, 5, 0, 0, 0, time.UTC))
	var closed []*Incident
	c.review = nil
	for _, cl := range closers {
		got, review := c.reg.CloseMatched(cl.Rule.ID, cl.Event, cl.Rule, "ротация", time.Now())
		closed = append(closed, got...)
		c.review = append(c.review, review...)
	}
	return closed
}

func (c *engineCycles) open() *Incident {
	for _, inc := range c.reg.open {
		return inc
	}
	return nil
}

// Сценарий 1: утечки A и B, ротация A, повторная утечка A,
// ротация B — каждый цикл по накопленному буферу. Инцидент открыт.
func TestEngineCyclesReleakAfterRotation(t *testing.T) {
	c := &engineCycles{t: t, r: secretEchoRule(t), reg: NewRegistry(0, nil)}
	leakEv := func(min int, secret, log string) *model.Event {
		return ciEvent(min, "gitlab.build.success", "group/project-A", secret, log)
	}
	rot := func(min int, secret string) *model.Event {
		return ciEvent(min, "gitlab.project_access_token_revoked", "group/project-A", secret, "")
	}
	steps := []struct {
		evs       []*model.Event
		wantClose bool
	}{
		{[]*model.Event{leakEv(1, "tok-A", "TOKEN=glpat-aaaaaaaaaaaa"), leakEv(2, "tok-B", "SECRET=bbbbbbbbbbbb")}, false},
		{[]*model.Event{rot(5, "tok-A")}, false},
		{[]*model.Event{leakEv(9, "tok-A", "TOKEN=glpat-a2a2a2a2a2a2")}, false},
		{[]*model.Event{rot(12, "tok-B")}, false}, // старая ротация A (:05) снова в буфере, но она раньше утечки :09
		{nil, false}, // пустой цикл: буфер тот же — по-прежнему открыт
		{[]*model.Event{rot(15, "tok-A")}, true},
	}
	for i, st := range steps {
		closed := c.cycle(st.evs...)
		if (len(closed) > 0) != st.wantClose {
			t.Fatalf("цикл %d: закрыто %d, ожидалось закрытие=%v", i, len(closed), st.wantClose)
		}
	}
}

// Сценарий 2: ротация на :05 и утечка на :09 попали в один
// цикл — ротация раньше утечки и её не отзывает.
func TestEngineCycleRotationBeforeLeakSameCycle(t *testing.T) {
	c := &engineCycles{t: t, r: secretEchoRule(t), reg: NewRegistry(0, nil)}
	if closed := c.cycle(ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa")); len(closed) != 0 {
		t.Fatal("утечка без ротации")
	}
	closed := c.cycle(
		ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", ""),
		ciEvent(9, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-a9a9a9a9a9a9"),
	)
	if len(closed) != 0 || c.open().Status == StatusClosed {
		t.Fatal("утечка :09 после ротации :05 — инцидент открыт")
	}
}

// Ротацию делает человек, а не бот, у которого утёк токен.
func TestRotationByHumanClosesSameSecret(t *testing.T) {
	c := &engineCycles{t: t, r: secretEchoRule(t), reg: NewRegistry(0, nil)}
	c.cycle(ciEvent(1, "gitlab.build.success", "group/project-A", "tok-A", "TOKEN=glpat-aaaaaaaaaaaa"))
	rot := ciEvent(5, "gitlab.project_access_token_revoked", "group/project-A", "tok-A", "")
	rot.ActorName = "i.petrov" // человек
	if closed := c.cycle(rot); len(closed) != 1 {
		t.Fatalf("отзыв того же секрета человеком закрывает: %d", len(closed))
	}
}

// Утечку печатает бот CI, а токен отзывает человек: субъект события ротации
// другой, привязку даёт ключ close_match (проект + секрет). Атрибуты — как у
// нормализатора GitLab (collector/internal/parse: secret_id = имя токена).
func TestRotationBySomeoneElseClosesSameSecret(t *testing.T) {
	reg, r, inc := leak(t, ciEvent(1, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=glrt-9f8a7b6c5d4e3f2a1b0c"))
	human := func(sec int, action, secretID string) *model.Event {
		e := ciEvent(sec, action, "sec/argus", secretID, "")
		e.ActorName, e.Source = "i.petrov", "gitlab.audit"
		e.Attrs["project"] = "sec/argus"
		return e
	}
	if got := rotate(reg, r, human(5, "gitlab.project_access_token_revoked", "DEPLOY_TOKEN")); got != nil {
		t.Fatal("ротация чужого токена закрыла утечку")
	}
	if inc.Status == StatusClosed {
		t.Fatal("инцидент закрыт чужой ротацией")
	}
	if got := rotate(reg, r, human(6, "gitlab.project_access_token_revoked", "registry_token")); got != inc || inc.Status != StatusClosed {
		t.Fatalf("ротация того же токена другим субъектом закрывает утечку: %v %s", got, inc.Status)
	}
}

func TestOneRotationClosesEveryIncidentWithThatSecret(t *testing.T) {
	r := secretEchoRule(t)
	a := ciEvent(1, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=glrt-aaaaaaaaaaaa")
	b := ciEvent(2, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=glrt-aaaaaaaaaaaa")
	b.ActorName = "project_8_bot"
	dets, _ := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: []*model.Event{a, b}})
	reg := NewRegistry(0, nil)
	if created, _, _ := reg.Apply(dets, time.Date(2026, 8, 14, 4, 30, 0, 0, time.UTC)); len(created) != 2 {
		t.Fatalf("два бота — два инцидента: %d", len(created))
	}
	_, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: []*model.Event{ciEvent(5, "gitlab.project_access_token_revoked", "sec/argus", "REGISTRY_TOKEN", "")}})
	if len(closers) != 1 {
		t.Fatalf("closers: %d", len(closers))
	}
	if got, _ := reg.CloseMatched(r.ID, closers[0].Event, r, "отзыв", time.Now()); len(got) != 2 {
		t.Fatalf("отзыв секрета закрывает оба инцидента с ним: %d", len(got))
	}
}

// Сквозной сценарий на событиях, которые дал нормализатор коллектора
// (fixtures/events/secret-rotation.ndjson, collector/internal/parse:
// TestSecretRotationFixture): REGISTRY_TOKEN создан задолго до утечки;
// утечка в логе CI — только имя переменной, связи с токеном нет. Ротация
// чужого DEPLOY_TOKEN — открыт; однофамилец, созданный и отозванный после
// утечки, и даже ротация настоящего токена — не закрывают, а эскалируют с
// пометкой «нужна проверка» (связь утечки с токеном не доказана).
func TestCollectorFixtureRotationNeedsReview(t *testing.T) {
	raw, err := os.ReadFile("../../../fixtures/events/secret-rotation.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	var evs []*model.Event
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e model.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatal(err)
		}
		e.Ensure()
		evs = append(evs, &e)
	}
	if len(evs) != 6 || evs[1].Attrs["secret_id"] == "" || evs[0].Attrs["token_id"] != "4702" {
		t.Fatalf("фикстура: %d событий, secret_id утечки %q", len(evs), evs[1].Attrs["secret_id"])
	}
	c := &engineCycles{t: t, r: secretEchoRule(t), reg: NewRegistry(0, nil)}
	if closed := c.cycle(evs[0], evs[1]); len(closed) != 0 || c.open() == nil {
		t.Fatal("утечка заводит открытый инцидент")
	}
	if closed := c.cycle(evs[2]); len(closed) != 0 || len(c.review) != 0 {
		t.Fatal("ротация чужого токена (DEPLOY_TOKEN) не касается утечки REGISTRY_TOKEN")
	}
	inc := c.open()
	if closed := c.cycle(evs[3], evs[4]); len(closed) != 0 || inc.Status == StatusClosed {
		t.Fatal("отзыв однофамильца REGISTRY_TOKEN закрыл инцидент")
	}
	if len(c.review) != 1 || inc.Status != StatusEscalated || !slices.Contains(inc.Tags, NeedsReviewTag) || !strings.Contains(inc.Note, "нужна проверка") {
		t.Fatalf("однофамилец: эскалация с пометкой «нужна проверка»: review=%d status=%s tags=%v", len(c.review), inc.Status, inc.Tags)
	}
	if c.cycle(); len(c.review) != 0 {
		t.Fatal("пометка — один раз, хотя отзыв однофамильца снова в буфере")
	}
	if closed := c.cycle(evs[5]); len(closed) != 0 || inc.Status == StatusClosed {
		t.Fatal("утечка из лога CI не связана с токеном — ротация не закрывает, даже настоящего")
	}
}

// Пробы обхода автозакрытия из ревью безопасности: каждый обход
// получает отказ — инцидент не закрывается, а уходит в «нужна проверка».
func TestSecondOpinionPreexistingDecoyDoesNotClose(t *testing.T) {
	// Утёкший секрет с токеном 4799 не связан: 4799 — давний однофамилец.
	created := ciEvent(0, "gitlab.project_access_token_created", "sec/argus", "REGISTRY_TOKEN", "")
	created.Attrs["token_id"] = "4799"
	leaked := unlinked(ciEvent(1, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=synthetic-value"))
	revoke := ciEvent(6, "gitlab.project_access_token_revoked", "sec/argus", "REGISTRY_TOKEN", "")
	revoke.Attrs["token_id"] = "4799"
	reg, r, inc := leak(t, created, leaked)
	closed, review := rotateReview(reg, r, revoke)
	if closed != nil || review != inc || inc.Status != StatusEscalated {
		t.Fatalf("давний однофамилец закрыл утечку: closed=%v review=%v status=%s", closed, review, inc.Status)
	}
}

func TestRevocationMustMatchTokenProviderAndInstance(t *testing.T) {
	leakEv := ciEvent(1, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=glrt-aaaaaaaaaaaa")
	revoke := func(mut func(e *model.Event)) *model.Event {
		e := ciEvent(6, "gitlab.project_access_token_revoked", "sec/argus", "REGISTRY_TOKEN", "")
		mut(e)
		return e
	}
	for name, ev := range map[string]*model.Event{
		"другой источник (не аудит)": revoke(func(e *model.Event) { e.Source = "other-system" }),
		"другой провайдер":           revoke(func(e *model.Event) { e.Vendor, e.Source = "Other", "other.audit" }),
		"другой экземпляр":           revoke(func(e *model.Event) { e.Attrs["instance"] = "gitlab.other" }),
		"другой token_id":            revoke(func(e *model.Event) { e.Attrs["token_id"] = "4799" }),
		"без экземпляра":             revoke(func(e *model.Event) { delete(e.Attrs, "instance") }),
		"ротация, а не отзыв":        revoke(func(e *model.Event) { e.Action = "gitlab.project_access_token_rotated" }),
	} {
		t.Run(name, func(t *testing.T) {
			reg, r, inc := leak(t, leakEv)
			closed, review := rotateReview(reg, r, ev)
			if closed != nil || review != inc || inc.Status != StatusEscalated || inc.Review == "" {
				t.Fatalf("closed=%v review=%v status=%s", closed, review, inc.Status)
			}
			if slices.Contains(r.Tags, NeedsReviewTag) {
				t.Fatal("метка инцидента попала в теги правила")
			}
		})
	}
	reg, r, inc := leak(t, leakEv)
	inc.Status = StatusInProgress
	if _, review := rotateReview(reg, r, revoke(func(e *model.Event) { e.Attrs["token_id"] = "4799" })); review != inc || inc.Status != StatusInProgress {
		t.Fatalf("человек работает — статус не трогаем: %s", inc.Status)
	}
	// Отзыв того же токена из аудита того же экземпляра — закрывает, и после пометки.
	if closed, _ := rotateReview(reg, r, revoke(func(*model.Event) {})); closed != inc {
		t.Fatal("доказанный отзыв закрывает")
	}
}

// Две утечки одного ключа с разными токенами — связь не доказана.
func TestLeaksWithDifferentTokensNeverAutoClose(t *testing.T) {
	a := ciEvent(1, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=glrt-aaaaaaaaaaaa")
	b := ciEvent(2, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=glrt-bbbbbbbbbbbb")
	b.Attrs["token_id"] = "id-other"
	reg, r, inc := leak(t, a, b)
	if closed, review := rotateReview(reg, r, ciEvent(6, "gitlab.project_access_token_revoked", "sec/argus", "REGISTRY_TOKEN", "")); closed != nil || review != inc {
		t.Fatalf("closed=%v review=%v", closed, review)
	}
}

// Регрессии второго мнения по 7037b1a (security-regression-7037b1a.patch).

// Секреты A и B; отзыв A подтверждён, затем приходит более старое событие A
// без связи с токеном. Подтверждение A сбрасывается, и отзыв B не закрывает.
func TestLateAmbiguousLeakInvalidatesConfirmation(t *testing.T) {
	a := ciEvent(1, "gitlab.build.success", "sec/argus", "FIRST_TOKEN", "FIRST_TOKEN=synthetic-value-A")
	b := ciEvent(2, "gitlab.build.success", "sec/argus", "SECOND_TOKEN", "SECOND_TOKEN=synthetic-value-B")
	reg, r, inc := leak(t, a, b)
	if closed, _ := rotateReview(reg, r, ciEvent(5, "gitlab.project_access_token_revoked", "sec/argus", "FIRST_TOKEN", "")); closed != nil {
		t.Fatal("второй секрет ещё открыт")
	}
	late := unlinked(ciEvent(0, "gitlab.build.success", "sec/argus", "FIRST_TOKEN", "FIRST_TOKEN=synthetic-value-other"))
	dets, _ := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: []*model.Event{late, a, b}})
	reg.Apply(dets, time.Date(2026, 8, 14, 4, 31, 0, 0, time.UTC))
	k, _ := r.CloseMatchKey(a)
	if inc.links[k] != nil || inc.confirmed[k] {
		t.Fatalf("событие без связи инвалидирует связь и подтверждение: link=%v confirmed=%v", inc.links[k], inc.confirmed[k])
	}
	closed, review := rotateReview(reg, r, ciEvent(6, "gitlab.project_access_token_revoked", "sec/argus", "SECOND_TOKEN", ""))
	if closed != nil || inc.Status == StatusClosed || review != inc {
		t.Fatalf("закрыт при недоказанной связи A: status=%s confirmed=%v", inc.Status, inc.confirmed)
	}
}

// allConfirmed требует действующую связь, даже если подтверждение осталось.
func TestAllConfirmedRequiresLiveLink(t *testing.T) {
	inc := &Incident{closeNeed: map[string]time.Time{"k": {}}, confirmed: map[string]bool{"k": true}, links: map[string]*secretLink{"k": nil}}
	if inc.allConfirmed() {
		t.Fatal("подтверждение без связи не закрывает")
	}
}

func TestFailedOrUnknownRevocationDoesNotClose(t *testing.T) {
	for _, outcome := range []string{"failure", "unknown", ""} {
		t.Run("outcome="+outcome, func(t *testing.T) {
			reg, r, inc := leak(t, ciEvent(1, "gitlab.build.success", "sec/argus", "REGISTRY_TOKEN", "REGISTRY_TOKEN=synthetic-value"))
			revoke := ciEvent(6, "gitlab.project_access_token_revoked", "sec/argus", "REGISTRY_TOKEN", "")
			revoke.Outcome = outcome
			closed, review := rotateReview(reg, r, revoke)
			if closed != nil || inc.Status == StatusClosed || review != inc {
				t.Fatalf("неуспешный отзыв закрыл инцидент: closed=%v status=%s", closed, inc.Status)
			}
		})
	}
}
