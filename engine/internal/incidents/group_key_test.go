package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Открытый инцидент, записанный до group_key (миграция 0034), восстанавливается
// без ключа группы: его забирает сработка группы, а не заводится дубль.
func TestGroupKeyAdoptsLegacyIncident(t *testing.T) {
	r := qnapStorageRule(t)
	first := qnapStorageEvent("QNAP-2", 3, 0)
	legacy := Incident{IncidentID: "INC-7", RuleID: r.ID, ActorName: "System", Node: "QNAP-2", Status: StatusNew,
		EventCount: 1, FirstTS: first.TS, LastTS: first.TS}
	reg := NewRegistry(7, []Incident{legacy})
	created, _, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{first}), first.Time().Add(time.Second))
	if len(created) != 0 {
		t.Fatalf("legacy incident must be adopted, got new: %+v", created)
	}
	second := qnapStorageEvent("QNAP-2", 4, 1)
	created, _, _ = reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{first, second}), second.Time().Add(time.Second))
	if len(created) != 1 || created[0].IncidentID == "INC-7" || created[0].GroupKey == "" {
		t.Fatalf("other disk after adoption needs its own incident: %+v", created)
	}
}

// Восстановленный с group_key инцидент совпадает с той же сработкой после рестарта.
func TestGroupKeySurvivesRestart(t *testing.T) {
	r := qnapStorageRule(t)
	ev := qnapStorageEvent("QNAP-2", 3, 0)
	dets := eval.Run([]*rules.Rule{r}, []*model.Event{ev})
	created, _, _ := NewRegistry(0, nil).Apply(dets, ev.Time().Add(time.Second))
	if len(created) != 1 || created[0].GroupKey == "" {
		t.Fatalf("grouped rule must carry group_key: %+v", created)
	}
	restored := *created[0]
	restored.Events = nil
	reg := NewRegistry(1, []Incident{restored})
	again, _, _ := reg.Apply(dets, ev.Time().Add(2*time.Second))
	if len(again) != 0 {
		t.Fatalf("same disk after restart must not open a duplicate: %+v", again)
	}
	if got := reg.Close(r.ID, created[0].GroupKey, "восстановлен", ev.Time().Add(time.Minute), ev.Time().Add(time.Minute)); got == nil || got.IncidentID != created[0].IncidentID {
		t.Fatalf("close_on by group key must close the disk incident: %+v", got)
	}
}

// Правило без явного group_by (и с group_by субъекта/адреса) ключ реестра не меняет.
func TestGroupKeyOnlyForExplicitNonActorGroup(t *testing.T) {
	for gb, want := range map[string]bool{"": false, "actor.name": false, "node": false, "src.ip": false, "dst.ip": false, "object": true, "node, object": true} {
		r := &rules.Rule{}
		r.Detection.GroupBy = gb
		if got := explicitGroup(r); got != want {
			t.Errorf("explicitGroup(%q) = %v, want %v", gb, got, want)
		}
	}
}
