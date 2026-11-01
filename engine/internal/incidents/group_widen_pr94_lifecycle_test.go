package incidents

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Controls for PR94: a plain textual prefix must not match across field
// boundaries, and neither final status is eligible for prefix adoption.
func TestPR94WidenedGroupPrefixBoundaryAndFinalStates(t *testing.T) {
	for _, tc := range []struct {
		name, oldPeer, nextPeer, status string
		wantAdopt                       bool
	}{
		{"open", "192.0.2.1", "192.0.2.1", StatusInProgress, true},
		{"text prefix only", "192.0.2.1", "192.0.2.10", StatusNew, false},
		{"different peer", "192.0.2.1", "192.0.2.2", StatusNew, false},
		{"closed", "192.0.2.1", "192.0.2.1", StatusClosed, false},
		{"false positive", "192.0.2.1", "192.0.2.1", StatusFalsePositive, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule, fixture := pr80ClockSkewFixture(t)
			legacy := *rule
			legacy.Detection.GroupBy = "attrs.peer"
			first := *fixture[0]
			first.Attrs = map[string]string{"peer": tc.oldPeer, "source": "net.vrp", "transport": "internal"}
			start := first.Time()
			old, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{&legacy}, []*model.Event{&first}), start)
			if len(old) != 1 {
				t.Fatalf("legacy fixture: %+v", old)
			}
			row := *old[0]
			row.Events, row.Status, row.Owner, row.Note = nil, tc.status, "reviewer", "Existing decision"
			reg := NewRegistry(1, []Incident{row})
			next := first
			next.TS = model.FormatTS(start.Add(time.Minute))
			next.Attrs = map[string]string{"peer": tc.nextPeer, "source": "net.vrp", "transport": "internal"}
			dets := eval.Run([]*rules.Rule{rule}, []*model.Event{&next})
			if len(dets) != 1 {
				t.Fatalf("new fixture: %+v", dets)
			}
			created, updated, _ := reg.Apply(dets, start.Add(2*time.Minute))
			if tc.wantAdopt {
				if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != row.IncidentID || updated[0].Status != row.Status || updated[0].Owner != row.Owner || updated[0].Note != row.Note {
					t.Fatalf("valid adoption lost the original decision: created=%+v updated=%+v", created, updated)
				}
			} else if len(created) != 1 || len(updated) != 0 || created[0].IncidentID == row.IncidentID {
				t.Fatalf("ineligible prefix was adopted: created=%+v updated=%+v", created, updated)
			}
		})
	}
}

// The engine serializes Apply -> Reconcile -> INSERT -> Persisted. Model a
// failed INSERT and an operator decision between adoption and its retry,
// without introducing an overlapping Apply that the engine never performs.
func TestPR94WidenedGroupPendingSurvivesFailedWrite(t *testing.T) {
	for _, operatorStatus := range []string{StatusWaitingOwner, StatusClosed, StatusFalsePositive} {
		for _, threshold := range []bool{false, true} {
			t.Run(fmt.Sprintf("status=%s/threshold=%t", operatorStatus, threshold), func(t *testing.T) {
				oldRule := compositeRegressionRule(t, "object", threshold)
				newRule := compositeRegressionRule(t, "object, attrs.detail", threshold)
				start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
				first := &model.Event{
					TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
					ActorName: "alice", Node: "edge", Object: "resource", Attrs: map[string]string{"detail": "first"},
				}
				old, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{oldRule}, []*model.Event{first}), start)
				if len(old) != 1 {
					t.Fatalf("legacy fixture: %+v", old)
				}
				row := *old[0]
				row.Events = nil
				reg := NewRegistry(1, []Incident{row})
				dets := eval.Run([]*rules.Rule{newRule}, []*model.Event{first})
				if len(dets) != 1 {
					t.Fatalf("new fixture: %+v", dets)
				}
				created, updated, _ := reg.Apply(dets, start.Add(time.Minute))
				if len(created) != 0 || len(updated) != 1 || updated[0].GroupKey != dets[0].Key || !updated[0].groupPending {
					t.Fatalf("unchanged evidence must still queue the widened key: created=%+v updated=%+v", created, updated)
				}
				adopted := updated[0]
				firstWriteStamp := adopted.UpdatedAt
				// INSERT fails: do not acknowledge it. The next buffer has lost
				// the original evidence but contains a different child group.
				sibling := *first
				sibling.TS = model.FormatTS(start.Add(2 * time.Minute))
				sibling.Attrs = map[string]string{"detail": "second"}
				created, updated, _ = reg.Apply(eval.Run([]*rules.Rule{newRule}, []*model.Event{&sibling}), start.Add(3*time.Minute))
				if len(created) != 1 || len(updated) != 1 || updated[0] != adopted || !adopted.groupPending || adopted.GroupKey != dets[0].Key || adopted.UpdatedAt <= firstWriteStamp {
					t.Fatalf("retry must preserve the adopted child and create the sibling: created=%+v updated=%+v", created, updated)
				}
				reg.Persisted(created) // A different incident's ACK must not clear the retry.
				if !adopted.groupPending {
					t.Fatal("persisting a sibling cleared the pending migration")
				}
				ops := map[string]Operator{row.IncidentID: {
					Status: operatorStatus, Owner: "operator", Note: "Decision during failed write",
					UpdatedAt: model.FormatTS(start.Add(2 * time.Minute))[:19],
				}}
				toWrite := reg.Reconcile(updated, ops, nil, start.Add(3*time.Minute))
				if adopted.Status != operatorStatus || adopted.Owner != "operator" || adopted.Note != ops[row.IncidentID].Note {
					t.Fatalf("migration overwrote the operator's decision: %+v", adopted)
				}
				if isFinal(operatorStatus) {
					if len(toWrite) != 0 || adopted.groupPending {
						t.Fatalf("final decision must settle the migration: rows=%+v pending=%t", toWrite, adopted.groupPending)
					}
				} else {
					if len(toWrite) != 1 || !adopted.groupPending {
						t.Fatalf("open decision must retain the pending write: %+v", toWrite)
					}
					reg.Persisted(toWrite)
				}
				stamp := adopted.UpdatedAt
				created, updated, _ = reg.Apply(nil, start.Add(4*time.Minute))
				if len(created)+len(updated) != 0 || adopted.UpdatedAt != stamp {
					t.Fatalf("settled migration must stop retrying: created=%+v updated=%+v", created, updated)
				}
			})
		}
	}
}
