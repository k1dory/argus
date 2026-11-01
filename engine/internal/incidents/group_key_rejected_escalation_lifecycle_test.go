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

// Exercise several full retry cycles after rejected escalation, including an
// operator completing the incident while its group key is still unpersisted.
func TestPR25RejectedEscalationRetrySettles(t *testing.T) {
	for _, status := range []string{StatusEscalated, StatusInProgress, StatusWaitingOwner, StatusObserving} {
		for _, finish := range []string{"persisted", StatusClosed, StatusFalsePositive} {
			t.Run(fmt.Sprintf("%s/%s", status, finish), func(t *testing.T) {
				rule := compositeRegressionRule(t, "actor.name, src.ip", false)
				rule.AutoClose, rule.AutoCloseAction = "1m", "escalate"
				policy := func(string) AutoClose { return AutoClose{After: time.Minute, Escalate: true} }
				start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
				event := &model.Event{TS: model.FormatTS(start), Source: "test", Action: "test.failure", ActorName: "admin", Node: "NAS-A", SrcIP: "192.0.2.10"}
				dets := eval.Run([]*rules.Rule{rule}, []*model.Event{event})
				if len(dets) != 1 {
					t.Fatalf("detections=%d", len(dets))
				}
				legacy := Incident{IncidentID: "INC-7", RuleID: rule.ID, Status: StatusNew, ActorName: event.ActorName, Node: event.Node,
					EventCount: 1, FirstTS: event.TS, LastTS: event.TS, CreatedAt: event.TS[:19], UpdatedAt: event.TS[:19]}
				reg := NewRegistry(7, []Incident{legacy})
				op := Operator{Status: status, Owner: "analyst", Note: "Operator decision", UpdatedAt: model.FormatTS(start.Add(30 * time.Second))[:19]}
				ops := map[string]Operator{legacy.IncidentID: op}
				now := start.Add(2 * time.Minute)
				created, updated, _ := reg.Apply(dets, now)
				if len(created) != 0 || len(updated) != 1 {
					t.Fatalf("adoption: created=%d updated=%d", len(created), len(updated))
				}
				adopted := updated[0]
				closed, escalated := reg.Sweep(policy, now)
				if len(closed) != 0 || len(escalated) != 1 {
					t.Fatalf("initial sweep: closed=%d escalated=%d", len(closed), len(escalated))
				}
				reg.Reconcile(append(updated, escalated...), ops, map[string]bool{legacy.IncidentID: true}, now)
				// No Persisted: the first write failed or reconciliation omitted it.
				for attempt := 3; attempt <= 5; attempt++ {
					now = start.Add(time.Duration(attempt) * time.Minute)
					created, updated, _ = reg.Apply(nil, now)
					if len(created) != 0 || len(updated) != 1 || updated[0] != adopted || adopted.GroupKey != dets[0].Key {
						t.Fatalf("attempt %d lost the original pending incident: created=%d updated=%+v", attempt, len(created), updated)
					}
					closed, escalated = reg.Sweep(policy, now)
					if len(closed)+len(escalated) != 0 {
						t.Fatalf("attempt %d repeated the rejected escalation", attempt)
					}
					rows := reg.Reconcile(updated, ops, nil, now)
					if len(rows) != 1 || adopted.Status != op.Status || adopted.Owner != op.Owner || adopted.Note != op.Note {
						t.Fatalf("attempt %d changed the operator decision: rows=%d incident=%+v", attempt, len(rows), adopted)
					}
					if got := reg.Prune(start.Add(48*time.Hour), 24*time.Hour, nil); got != 0 {
						t.Fatalf("pending open incident was pruned: %d", got)
					}
				}
				if finish != "persisted" {
					op.Status = finish
					ops[legacy.IncidentID] = op
				}
				now = start.Add(6 * time.Minute)
				_, updated, _ = reg.Apply(nil, now)
				rows := reg.Reconcile(updated, ops, nil, now)
				if finish != "persisted" && len(rows) != 0 {
					t.Fatalf("operator's final state must cancel retry: rows=%d", len(rows))
				}
				var persisted []Incident
				if finish == "persisted" {
					if len(rows) != 1 {
						t.Fatalf("recovered write missing: rows=%d", len(rows))
					}
					raw, err := json.Marshal(rows)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(raw, &persisted); err != nil {
						t.Fatal(err)
					}
					reg.Persisted(rows)
				}
				stamp := adopted.UpdatedAt
				for _, offset := range []time.Duration{7 * time.Minute, time.Hour, 25 * time.Hour} {
					for _, buffer := range [][]eval.Detection{nil, dets} {
						created, updated, _ = reg.Apply(buffer, start.Add(offset))
						if len(created)+len(updated) != 0 || adopted.UpdatedAt != stamp {
							t.Fatalf("settled incident still changes after %s: created=%d updated=%d stamp=%s want=%s", offset, len(created), len(updated), adopted.UpdatedAt, stamp)
						}
					}
				}
				wantPruned := 0
				if finish != "persisted" {
					wantPruned = 1
				}
				if got := reg.Prune(start.Add(26*time.Hour), 24*time.Hour, nil); got != wantPruned {
					t.Fatalf("pruned=%d want=%d", got, wantPruned)
				}
				if finish == "persisted" {
					restarted := NewRegistry(7, persisted)
					created, updated, _ = restarted.Apply(dets, start.Add(26*time.Hour))
					if len(created)+len(updated) != 0 {
						t.Fatal("same group changed after restart")
					}
					other := *event
					other.SrcIP, other.TS = "198.51.100.20", model.FormatTS(start.Add(26*time.Hour))
					created, _, _ = restarted.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{&other}), other.Time())
					if len(created) != 1 || created[0].IncidentID == legacy.IncidentID {
						t.Fatal("different group failed to create its own incident after restart")
					}
				}
			})
		}
	}
}
