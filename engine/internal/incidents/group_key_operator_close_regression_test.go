package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// An operator can finish an incident after startup loaded its old open state,
// but before the first group-key adoption is written. Reconcile must settle
// that adoption: an idle registry must not keep refreshing a final incident
// forever and thereby prevent the engine's 24-hour Prune from removing it.
func TestPR21GroupKeyOperatorCloseDoesNotKeepRetrying(t *testing.T) {
	for _, status := range []string{StatusClosed, StatusFalsePositive} {
		t.Run(status, func(t *testing.T) {
			rule := qnapStorageRule(t)
			first := qnapStorageEvent("QNAP-2", 3, 0)
			start := first.Time()
			legacy := Incident{
				IncidentID: "INC-7", RuleID: rule.ID, ActorName: first.ActorName, Node: first.Node,
				Status: StatusNew, EventCount: 1, FirstTS: first.TS, LastTS: first.TS,
				CreatedAt: first.TS[:19], UpdatedAt: first.TS[:19],
			}
			reg := NewRegistry(7, []Incident{legacy})
			dets := eval.Run([]*rules.Rule{rule}, []*model.Event{first})
			created, updated, _ := reg.Apply(dets, start.Add(time.Minute))
			if len(created) != 0 || len(updated) != 1 {
				t.Fatalf("initial adoption: created=%d updated=%d", len(created), len(updated))
			}
			adopted := updated[0]
			ops := map[string]Operator{
				legacy.IncidentID: {
					Status: status, Owner: "analyst", Note: "Reviewed and resolved",
					UpdatedAt: "2026-10-30 12:00:30",
				},
			}
			// Mirror writeIncidents: reconcile first, acknowledge only rows that
			// actually survive reconciliation and a successful INSERT.
			write := func(rows []*Incident, now time.Time) {
				t.Helper()
				toWrite := reg.Reconcile(rows, ops, nil, now)
				for _, inc := range toWrite {
					if inc.Status != status || inc.Owner != "analyst" || inc.Note != "Reviewed and resolved" {
						t.Fatalf("metadata adoption must preserve the operator's decision: %+v", inc)
					}
				}
				if len(toWrite) > 0 {
					reg.Persisted(toWrite)
				}
			}
			write(updated, start.Add(time.Minute))
			if adopted.Status != status {
				t.Fatalf("operator state was not reconciled: %+v", adopted)
			}
			settledStamp := adopted.UpdatedAt

			// The original detection has expired or was evicted; the database
			// is healthy and still reports the same final operator state.
			for _, offset := range []time.Duration{2 * time.Minute, 25 * time.Hour} {
				now := start.Add(offset)
				created, updated, _ = reg.Apply(nil, now)
				write(updated, now)
				if len(created) != 0 || len(updated) != 0 {
					t.Errorf("final incident still retried after %s without evidence: created=%d updated=%d", offset, len(created), len(updated))
				}
				if adopted.UpdatedAt != settledStamp {
					t.Errorf("idle final incident's timestamp drifted after %s: got %q, want %q", offset, adopted.UpdatedAt, settledStamp)
				}
			}
			if n := reg.Prune(start.Add(25*time.Hour), 24*time.Hour, nil); n != 1 {
				t.Errorf("operator-closed incident must expire after 24 hours, pruned=%d; groupPending=%t updated_at=%q", n, adopted.groupPending, adopted.UpdatedAt)
			}
		})
	}
}
