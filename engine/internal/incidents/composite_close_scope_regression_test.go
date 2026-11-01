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

// Adding GroupKey changes the registry key from rule|actor|node to
// rule|actor|node|group. A close_on key actor|node now matches the legacy
// prefix fallback even when the incident's explicit actor|src.ip group is
// different. A node named by its address is normal for network log sources.
func TestPR21CompositeCloseOnCannotCloseAnotherAddressGroup(t *testing.T) {
	for _, threshold := range []bool{false, true} {
		for _, restart := range []bool{false, true} {
			for _, matchingGroup := range []bool{false, true} {
				name := fmt.Sprintf("threshold=%t/restart=%t/matching_group=%t", threshold, restart, matchingGroup)
				t.Run(name, func(t *testing.T) {
					rule := compositeRegressionRule(t, "actor.name, src.ip", threshold)
					start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
					failure := &model.Event{
						TS: model.FormatTS(start), Source: "test", Action: "test.failure",
						ActorName: "admin", Node: "192.0.2.10", SrcIP: "198.51.100.20",
					}
					reg := NewRegistry(0, nil)
					created, _, _ := reg.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{failure}), start)
					if len(created) != 1 {
						t.Fatalf("expected one open incident: %+v", created)
					}
					incidentID := created[0].IncidentID
					reg.Persisted(created)
					if restart {
						// Persisted JSON omits Events and all in-memory retry state.
						raw, err := json.Marshal(created[0])
						if err != nil {
							t.Fatal(err)
						}
						var restored Incident
						if err := json.Unmarshal(raw, &restored); err != nil {
							t.Fatal(err)
						}
						reg = NewRegistry(1, []Incident{restored})
					}

					recovery := *failure
					recovery.Action = "test.recovery"
					recovery.TS = model.FormatTS(start.Add(time.Minute))
					if !matchingGroup {
						// A local recovery belongs to admin|192.0.2.10, not to
						// the outstanding failure from admin|198.51.100.20.
						recovery.SrcIP = failure.Node
					}
					_, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{rule}, Events: []*model.Event{&recovery}})
					if len(closers) != 1 {
						t.Fatalf("expected one recovery event: %+v", closers)
					}
					closer := closers[0]
					closed := reg.Close(rule.ID, closer.Key, "recovered", closer.Event.Time(), start.Add(2*time.Minute))
					if matchingGroup {
						if closed == nil || closed.IncidentID != incidentID || closed.Status != StatusClosed {
							t.Fatalf("matching group must still close %s: %+v", incidentID, closed)
						}
						return
					}
					if closed != nil {
						t.Fatalf("recovery for %q closed another group %q (%s): the explicit group must take precedence over the legacy prefix", closer.Key, closed.GroupKey, closed.IncidentID)
					}
					if open := reg.OpenByRule(rule.ID); open == nil || open.IncidentID != incidentID || open.Status != StatusNew {
						t.Fatalf("foreign recovery changed the outstanding incident: %+v", open)
					}
				})
			}
		}
	}
}
