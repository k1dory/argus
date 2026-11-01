package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Apply's returned rows are the engine's persistence boundary. Adopting a
// legacy incident must produce an update even when its evidence was already
// stored; an in-memory key alone disappears at the next restart.
func TestGroupKeyLegacyAdoptionPersistsBeforeRestart(t *testing.T) {
	rule := qnapStorageRule(t)
	first := qnapStorageEvent("QNAP-2", 3, 0)
	dets := eval.Run([]*rules.Rule{rule}, []*model.Event{first})
	if len(dets) != 1 || dets[0].Key == "" {
		t.Fatalf("first disk detection: %+v", dets)
	}
	legacy := Incident{
		IncidentID: "INC-7", RuleID: rule.ID, ActorName: "System", Node: "QNAP-2", Status: StatusNew,
		EventCount: 1, FirstTS: first.TS, LastTS: first.TS,
		CreatedAt: first.TS[:19], UpdatedAt: first.TS[:19],
	}
	persisted := legacy
	reg := NewRegistry(7, []Incident{legacy})
	created, updated, _ := reg.Apply(dets, first.Time().Add(time.Minute))
	if len(created) != 0 {
		t.Errorf("legacy adoption created duplicate incidents: %+v", created)
	}
	if len(updated) != 1 {
		t.Errorf("legacy group adoption must be persisted without new evidence: updated=%d, want 1", len(updated))
	}
	for _, row := range updated {
		if row.IncidentID == legacy.IncidentID {
			persisted = *row
			persisted.Events = nil // Events are not stored in incidents.
		}
	}
	if persisted.GroupKey != dets[0].Key {
		t.Errorf("persisted group_key=%q, want first disk group %q", persisted.GroupKey, dets[0].Key)
	}
	if persisted.UpdatedAt <= legacy.UpdatedAt {
		t.Errorf("adoption must advance the persisted version: updated_at=%q, previous=%q", persisted.UpdatedAt, legacy.UpdatedAt)
	}

	// After another restart, the first disk is outside the evaluation window.
	// Only a fault on a different disk arrives; it must not adopt INC-7 again.
	restarted := NewRegistry(7, []Incident{persisted})
	second := qnapStorageEvent("QNAP-2", 4, 1)
	second.TS = model.FormatTS(first.Time().Add(25 * time.Hour))
	created, updated, _ = restarted.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{second}), second.Time().Add(time.Second))
	if len(created) != 1 {
		t.Fatalf("different disk after restart needs a new incident/notification: created=%d updated=%d; first disk must keep INC-7", len(created), len(updated))
	}
	if created[0].IncidentID == legacy.IncidentID || created[0].GroupKey == dets[0].Key {
		t.Fatalf("different disk reused legacy identity: %+v", created[0])
	}
}
