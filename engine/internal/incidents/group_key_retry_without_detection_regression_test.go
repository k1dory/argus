package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// The persistence obligation survives the event buffer: a failed INSERT may
// recover after the original evidence expires or is evicted by ENGINE_BUFFER_MAX.
func TestGroupKeyRetryWithoutOriginalDetection(t *testing.T) {
	for _, nextCycle := range []string{"empty buffer", "only another disk"} {
		t.Run(nextCycle, func(t *testing.T) {
			rule := qnapStorageRule(t)
			first := qnapStorageEvent("QNAP-2", 3, 0)
			dets := eval.Run([]*rules.Rule{rule}, []*model.Event{first})
			if len(dets) != 1 {
				t.Fatalf("initial detections=%d, want 1", len(dets))
			}
			legacy := Incident{
				IncidentID: "INC-7", RuleID: rule.ID, ActorName: first.ActorName, Node: first.Node,
				Status: StatusNew, EventCount: 1, FirstTS: first.TS, LastTS: first.TS,
				CreatedAt: first.TS[:19], UpdatedAt: first.TS[:19],
			}
			reg := NewRegistry(7, []Incident{legacy})
			created, updated, _ := reg.Apply(dets, first.Time().Add(time.Minute))
			if len(created) != 0 || len(updated) != 1 || updated[0].GroupKey != dets[0].Key {
				t.Fatalf("initial group adoption: created=%d updated=%+v", len(created), updated)
			}
			// The INSERT failed, so the engine must not call Persisted(updated).
			// No copy of the original evidence remains on its next evaluation.
			var next []eval.Detection
			wantCreated := 0
			if nextCycle == "only another disk" {
				second := qnapStorageEvent("QNAP-2", 4, 1)
				next = eval.Run([]*rules.Rule{rule}, []*model.Event{second})
				wantCreated = 1
			}
			created, updated, _ = reg.Apply(next, first.Time().Add(2*time.Minute))
			if len(created) != wantCreated {
				t.Fatalf("new incidents=%d, want %d", len(created), wantCreated)
			}
			if len(updated) != 1 || updated[0].IncidentID != legacy.IncidentID || updated[0].GroupKey != dets[0].Key {
				t.Fatalf("failed adoption must be retried even without its detection; updated=%+v, want %s with group %q", updated, legacy.IncidentID, dets[0].Key)
			}
			if updated[0].UpdatedAt <= legacy.UpdatedAt {
				t.Fatalf("retry must still supersede the persisted legacy row: %+v", updated[0])
			}
			reg.Persisted(updated)
			_, updated, _ = reg.Apply(nil, first.Time().Add(3*time.Minute))
			if len(updated) != 0 {
				t.Fatalf("acknowledged adoption must leave the retry queue: %+v", updated)
			}
		})
	}
}

// A successful INSERT must stop both retries and artificial updated_at changes,
// even while the same evidence is replayed on every engine cycle.
func TestGroupKeyPersistedStopsTimestampDrift(t *testing.T) {
	rule := qnapStorageRule(t)
	first := qnapStorageEvent("QNAP-2", 3, 0)
	dets := eval.Run([]*rules.Rule{rule}, []*model.Event{first})
	legacy := Incident{
		IncidentID: "INC-7", RuleID: rule.ID, ActorName: first.ActorName, Node: first.Node,
		Status: StatusNew, EventCount: 1, FirstTS: first.TS, LastTS: first.TS,
		CreatedAt: first.TS[:19], UpdatedAt: first.TS[:19],
	}
	reg := NewRegistry(7, []Incident{legacy})
	created, updated, _ := reg.Apply(dets, first.Time().Add(time.Minute))
	if len(created) != 0 || len(updated) != 1 {
		t.Fatalf("initial group adoption: created=%d updated=%d", len(created), len(updated))
	}
	adopted := updated[0]
	stamp := adopted.UpdatedAt
	reg.Persisted(updated)
	for _, offset := range []time.Duration{2 * time.Minute, time.Hour, 24 * time.Hour} {
		created, updated, _ = reg.Apply(dets, first.Time().Add(offset))
		if len(created)+len(updated) != 0 || adopted.UpdatedAt != stamp {
			t.Fatalf("persisted adoption changed on replay after %s: created=%d updated=%d stamp=%q, want %q", offset, len(created), len(updated), adopted.UpdatedAt, stamp)
		}
	}
}
