package incidents

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Rejecting an automatic escalation must not acknowledge an unwritten group
// key for an OPEN incident. The engine queues both Apply's update and Sweep's
// escalation, reconciles them, and acknowledges only a successful INSERT.
// An operator's already-escalated status drops both rows; other open operator
// statuses leave a row whose INSERT can fail. Neither case settles adoption.
func TestPR21RejectedEscalationKeepsGroupKeyRetry(t *testing.T) {
	for _, status := range []string{
		StatusEscalated, StatusInProgress, StatusWaitingOwner, StatusObserving,
		StatusNew, StatusClosed, StatusFalsePositive, // Accepted escalation and final-state controls.
	} {
		for _, insertFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("operator=%s/insert_fails=%t", status, insertFails), func(t *testing.T) {
				rule := compositeRegressionRule(t, "actor.name, src.ip", false)
				rule.AutoClose, rule.AutoCloseAction = "1m", "escalate"
				start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
				failure := &model.Event{
					TS: model.FormatTS(start), Source: "test", Action: "test.failure",
					ActorName: "admin", Node: "NAS-A", SrcIP: "192.0.2.10",
				}
				dets := eval.Run([]*rules.Rule{rule}, []*model.Event{failure})
				if len(dets) != 1 {
					t.Fatalf("fixture needs one detection, got %d", len(dets))
				}
				legacy := Incident{
					IncidentID: "INC-7", RuleID: rule.ID, ActorName: failure.ActorName, Node: failure.Node,
					Status: StatusNew, EventCount: 1, FirstTS: failure.TS, LastTS: failure.TS,
					CreatedAt: failure.TS[:19], UpdatedAt: failure.TS[:19],
				}
				reg := NewRegistry(7, []Incident{legacy})
				// The operator changes the persisted state after the engine loaded it.
				op := Operator{
					Status: status, Owner: "analyst", Note: "Operator decision",
					UpdatedAt: model.FormatTS(start.Add(30 * time.Second))[:19],
				}
				ops := map[string]Operator{legacy.IncidentID: op}
				persisted := legacy
				persisted.Status, persisted.Owner, persisted.Note, persisted.UpdatedAt = op.Status, op.Owner, op.Note, op.UpdatedAt
				persist := func(rows []*Incident) {
					t.Helper()
					for _, inc := range rows {
						data, err := json.Marshal(inc)
						if err != nil {
							t.Fatal(err)
						}
						// A database round trip drops Events and in-memory retry state.
						persisted = Incident{}
						if err := json.Unmarshal(data, &persisted); err != nil {
							t.Fatal(err)
						}
					}
					reg.Persisted(rows)
				}

				now := start.Add(2 * time.Minute)
				created, updated, _ := reg.Apply(dets, now)
				if len(created) != 0 || len(updated) != 1 || updated[0].GroupKey != dets[0].Key {
					t.Fatalf("legacy adoption: created=%d updated=%+v", len(created), updated)
				}
				adopted := updated[0]
				closed, escalated := reg.Sweep(func(string) AutoClose {
					return AutoClose{After: rule.AutoCloseAfter(), Escalate: rule.AutoCloseEscalates()}
				}, now)
				if len(closed) != 0 || len(escalated) != 1 || escalated[0] != adopted {
					t.Fatalf("fixture must queue an escalation of the adopted incident: closed=%d escalated=%+v", len(closed), escalated)
				}
				// Match engine.cycle's ordering, including its two references to the
				// same incident. Testing a single artificial row misses this behavior.
				toWrite := append(updated, escalated...)
				toWrite = reg.Reconcile(toWrite, ops, map[string]bool{legacy.IncidentID: true}, now)
				wantStatus := status
				if status == StatusNew {
					wantStatus = StatusEscalated
				}
				if adopted.Status != wantStatus || adopted.Owner != op.Owner {
					t.Fatalf("reconciliation changed the operator decision: %+v", adopted)
				}
				if status != StatusNew && adopted.Note != op.Note {
					t.Fatalf("rejected escalation must preserve the operator note: %q", adopted.Note)
				}
				if !insertFails {
					persist(toWrite)
				}

				// The original evidence has left the buffer. A recovered database
				// must still receive the adopted key, unless the operator closed it.
				stamp := adopted.UpdatedAt
				later := now.Add(time.Minute)
				created, updated, _ = reg.Apply(nil, later)
				if len(created) != 0 {
					t.Fatalf("idle retry created incidents: %+v", created)
				}
				if isFinal(status) {
					if len(updated) != 0 || adopted.UpdatedAt != stamp {
						t.Fatalf("operator-closed incident must stop retrying: updated=%d stamp=%q, want %q", len(updated), adopted.UpdatedAt, stamp)
					}
					if n := reg.Prune(start.Add(25*time.Hour), 24*time.Hour, nil); n != 1 {
						t.Fatalf("settled final incident must be prunable, got %d", n)
					}
					return
				}
				if persisted.GroupKey == "" {
					if len(updated) != 1 || updated[0] != adopted {
						t.Errorf("open incident lost its unwritten group-key retry: operator=%s writes=%d retry=%d", status, len(toWrite), len(updated))
					}
				} else if len(updated) != 0 || adopted.UpdatedAt != stamp {
					t.Errorf("successful INSERT must settle adoption: updated=%d stamp=%q, want %q", len(updated), adopted.UpdatedAt, stamp)
				}
				persist(reg.Reconcile(updated, ops, nil, later))
				if persisted.GroupKey != dets[0].Key {
					t.Errorf("healthy database never received the adopted key: got %q, want %q", persisted.GroupKey, dets[0].Key)
				}

				// Demonstrate the consequence at the notification boundary: after
				// restart a different address must create its own incident, rather
				// than silently claim the still-keyless legacy incident.
				restarted := NewRegistry(7, []Incident{persisted})
				other := *failure
				other.SrcIP, other.TS = "198.51.100.20", model.FormatTS(start.Add(25*time.Hour))
				created, updated, _ = restarted.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{&other}), other.Time())
				if len(created) != 1 || created[0].IncidentID == legacy.IncidentID {
					t.Errorf("different address after restart lost its separate incident/notification: created=%d updated=%d persisted_group=%q", len(created), len(updated), persisted.GroupKey)
				}
			})
		}
	}
}
