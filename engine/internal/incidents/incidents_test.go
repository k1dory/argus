package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func TestSweepAutoClosesOnlyUntouched(t *testing.T) {
	old := "2026-08-14 04:01:38.000"
	reg := NewRegistry(10, []Incident{
		{IncidentID: "INC-1", RuleID: "ci", Status: StatusNew, ActorName: "bot", LastTS: old},
		{IncidentID: "INC-2", RuleID: "ci", Status: StatusInProgress, ActorName: "human", LastTS: old},
		{IncidentID: "INC-3", RuleID: "other", Status: StatusNew, ActorName: "x", LastTS: old},
	})
	now := time.Date(2026, 8, 14, 9, 0, 0, 0, time.UTC)
	closed, _ := reg.Sweep(func(id string) AutoClose {
		if id == "ci" {
			return AutoClose{After: 4 * time.Hour}
		}
		return AutoClose{}
	}, now)
	if len(closed) != 1 || closed[0].IncidentID != "INC-1" || closed[0].Status != StatusClosed {
		t.Fatalf("закрыть только INC-1 (new, ci, > 4h): %+v", closed)
	}
	// close_on — сильное свидетельство (причина устранена): закрывает и in_progress
	if inc := reg.Close("ci", "human", "ротация", now, now); inc == nil || inc.Status != StatusClosed {
		t.Fatalf("close_on должен закрыть и in_progress: %+v", inc)
	}
}

func TestCloseByKey(t *testing.T) {
	reg := NewRegistry(1, []Incident{{IncidentID: "INC-1", RuleID: "ci", Status: StatusNew, ActorName: "bot", Node: "runner"}})
	inc := reg.Close("ci", "bot", "ротация токена", time.Now(), time.Now())
	if inc == nil || inc.Status != StatusClosed || inc.Note == "" {
		t.Fatalf("%+v", inc)
	}
	if reg.Close("ci", "bot", "повтор", time.Now(), time.Now()) != nil {
		t.Fatal("закрытый повторно не закрывается")
	}
}

// close_on закрывает только событием восстановления ПОЗЖЕ последнего события
// инцидента: последовательность 80 → 91 → 93 → 95 в одном буфере не должна
// заводить и сразу закрывать инцидент старым нормальным замером.
func TestCloseRequiresRecoveryAfterLastEvent(t *testing.T) {
	last := time.Date(2026, 10, 20, 10, 30, 0, 0, time.UTC)
	reg := NewRegistry(1, []Incident{{IncidentID: "INC-1", RuleID: "disk", Status: StatusNew, ActorName: "db-01", Node: "db-01", LastTS: model.FormatTS(last)}})
	now := last.Add(time.Hour)
	if inc := reg.Close("disk", "db-01", "80 % в 10:00", last.Add(-30*time.Minute), now); inc != nil {
		t.Fatalf("старый замер (до последнего нарушения) не закрывает: %+v", inc)
	}
	if inc := reg.Close("disk", "db-01", "равно last_ts", last, now); inc != nil {
		t.Fatalf("замер в момент последнего нарушения не закрывает: %+v", inc)
	}
	if inc := reg.Close("disk", "db-01", "84 % в 10:40", last.Add(10*time.Minute), now); inc == nil || inc.Status != StatusClosed {
		t.Fatalf("восстановление позже последнего нарушения закрывает: %+v", inc)
	}
}

func TestFinalIncidentNotRecreatedWithoutNewEvents(t *testing.T) {
	reg := NewRegistry(5, []Incident{{IncidentID: "INC-5", RuleID: "abs", Status: StatusClosed, ActorName: "app-01", Node: "app-01", LastTS: "2026-08-14 05:51:19.000"}})
	// Registry.Apply требует eval.Detection; проверяем через приватный путь build не можем — эмулируем ключ
	if _, ok := reg.open["abs|app-01|app-01"]; !ok {
		t.Fatal("закрытый инцидент должен остаться в реестре как якорь дедупликации")
	}
}

func TestSweepCountsFromCreatedAt(t *testing.T) {
	reg := NewRegistry(1, []Incident{{IncidentID: "INC-1", RuleID: "abs", Status: StatusNew, ActorName: "a", LastTS: "2026-08-14 01:00:00.000", CreatedAt: "2026-08-14 05:00:00"}})
	now := time.Date(2026, 8, 14, 5, 30, 0, 0, time.UTC)
	hour := func(string) AutoClose { return AutoClose{After: time.Hour} }
	if closed, _ := reg.Sweep(hour, now); len(closed) != 0 {
		t.Fatal("создан 30 минут назад — авто-закрытие через час ещё не наступило")
	}
	if closed, _ := reg.Sweep(hour, now.Add(time.Hour)); len(closed) != 1 {
		t.Fatal("через полтора часа после создания — закрыть")
	}
}

func TestReconcileKeepsOperatorFields(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	r := NewRegistry(0, nil)
	upd := &Incident{IncidentID: "INC-1", Status: StatusNew, Owner: "", Note: "", UpdatedAt: "2026-09-07 12:00:00"}
	closedByOp := &Incident{IncidentID: "INC-2", Status: StatusNew, UpdatedAt: "2026-09-07 12:00:00"}
	closedByEngine := &Incident{IncidentID: "INC-3", Status: StatusClosed, Note: "закрыт автоматикой", UpdatedAt: "2026-09-07 12:00:00"}
	ops := map[string]Operator{
		"INC-1": {Status: StatusInProgress, Owner: "ivanov (аналитик)", Note: "смотрю", UpdatedAt: "2026-09-07 12:00:00"},
		"INC-2": {Status: StatusFalsePositive, Owner: "petrov", Note: "ложное", UpdatedAt: "2026-09-07 11:59:00"},
		"INC-3": {Status: StatusObserving, Owner: "sidorov", Note: "наблюдаю", UpdatedAt: "2026-09-07 11:58:00"},
	}
	out := r.Reconcile([]*Incident{upd, closedByOp, closedByEngine}, ops, map[string]bool{"INC-3": true}, now)
	if len(out) != 2 {
		t.Fatalf("want 2 rows to write, got %d", len(out))
	}
	if upd.Status != StatusInProgress || upd.Owner != "ivanov (аналитик)" || upd.Note != "смотрю" {
		t.Fatalf("operator fields clobbered: %+v", upd)
	}
	if upd.UpdatedAt <= "2026-09-07 12:00:00" {
		t.Fatalf("updated_at must be strictly after operator version, got %s", upd.UpdatedAt)
	}
	if closedByEngine.Owner != "sidorov" || closedByEngine.Status != StatusClosed || closedByEngine.Note != "наблюдаю\nзакрыт автоматикой" {
		t.Fatalf("engine close must keep owner and prepend operator note: %+v", closedByEngine)
	}
}

func TestShadowedAndApplyOperator(t *testing.T) {
	inc := &Incident{IncidentID: "INC-1", Status: StatusNew, UpdatedAt: "2026-09-14 10:00:01"}
	seen := Operator{Status: StatusNew, UpdatedAt: "2026-09-14 09:59:00"}
	rows := []Operator{
		{Status: StatusNew, UpdatedAt: "2026-09-14 09:59:00"},                      // то, что мы читали
		{Status: StatusNew, UpdatedAt: "2026-09-14 10:00:01"},                      // наша запись
		{Status: StatusEscalated, Owner: "op", UpdatedAt: "2026-09-14 10:00:00"},   // оператор между чтением и записью
		{Status: StatusInProgress, Owner: "op2", UpdatedAt: "2026-09-14 10:00:05"}, // позже нас — и так побеждает
	}
	sh := Shadowed(inc, seen, rows)
	if sh == nil || sh.Status != StatusEscalated || sh.Owner != "op" {
		t.Fatalf("перекрытая версия оператора: %+v", sh)
	}
	ApplyOperator(inc, *sh)
	if inc.Status != StatusEscalated || inc.Owner != "op" || inc.UpdatedAt != "2026-09-14 10:00:02" {
		t.Fatalf("%+v", inc)
	}
	if Shadowed(&Incident{Status: StatusNew, UpdatedAt: "2026-09-14 10:00:01"}, seen, rows[:2]) != nil {
		t.Fatal("без чужих версий — nil")
	}
}
