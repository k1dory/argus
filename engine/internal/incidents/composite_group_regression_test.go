package incidents

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func compositeRegressionRule(t *testing.T, groupBy string, threshold bool) *rules.Rule {
	t.Helper()
	grouping := fmt.Sprintf("  group_by: %q\n  condition: selection\n", groupBy)
	if threshold {
		grouping = fmt.Sprintf("  threshold:\n    kind: count\n    count: 1\n    window: 5m\n    group_by: %q\n  condition: selection and threshold\n", groupBy)
	}
	yml := "title: Composite grouping regression\nid: composite-regression\nlevel: high\ndetection:\n  selection: {action: test.failure}\n" + grouping + "close_on:\n  action: test.recovery\n"
	path := filepath.Join(t.TempDir(), "composite.yml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	rule, err := rules.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

// An IP in a composite group is not represented by ActorName: build only moves
// d.Key there for the single-field src.ip/dst.ip groups. Losing the composite
// key suppresses the second incident and therefore its created notification.
func TestCompositeAddressGroupsCreateIndependentIncidents(t *testing.T) {
	for _, threshold := range []bool{false, true} {
		for _, groupBy := range []string{
			"actor.name, src.ip", "actor.name, dst.ip", "node, src.ip", "src.ip, dst.ip",
			"src.ip", "dst.ip", // Existing scalar groups are positive controls.
		} {
			t.Run(fmt.Sprintf("threshold=%t/%s", threshold, groupBy), func(t *testing.T) {
				rule := compositeRegressionRule(t, groupBy, threshold)
				start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
				first := &model.Event{
					TS: model.FormatTS(start), Source: "test", Action: "test.failure",
					ActorName: "admin", Node: "NAS-A", SrcIP: "192.0.2.10", DstIP: "198.51.100.10",
				}
				second := *first
				second.TS = model.FormatTS(start.Add(time.Second))
				second.SrcIP, second.DstIP = "192.0.2.11", "198.51.100.11"
				reg := NewRegistry(0, nil)
				created, _, _ := reg.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{first}), start)
				if len(created) != 1 {
					t.Fatalf("first incident: %+v", created)
				}
				firstIncident := created[0]
				reg.Persisted(created)
				dets := eval.Run([]*rules.Rule{rule}, []*model.Event{first, &second})
				if len(dets) != 2 || dets[0].Key == dets[1].Key {
					t.Fatalf("fixture must produce two independent detections: %+v", dets)
				}
				created, updated, _ := reg.Apply(dets, start.Add(2*time.Second))
				if len(created) != 1 || created[0].IncidentID == firstIncident.IncidentID {
					t.Fatalf("group_by %q: second address needs a separate incident/notification; created=%d updated=%d", groupBy, len(created), len(updated))
				}
				if firstIncident.LastTS != first.TS || len(firstIncident.Events) != 1 || firstIncident.Events[0] != first {
					t.Fatalf("second address overwrote the first incident's evidence: %+v", firstIncident)
				}
			})
		}
	}
}

// Omitting GroupKey for actor.name+node must not make close_on's composite key
// unresolvable. Check both fresh and restored registries with two local users.
func TestCompositeActorNodeCloseOnFindsIncident(t *testing.T) {
	for _, groupBy := range []string{"actor.name, node", "node, actor.name", "node, object"} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%t", groupBy, restart), func(t *testing.T) {
				rule := compositeRegressionRule(t, groupBy, false)
				start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
				first := &model.Event{
					TS: model.FormatTS(start), Source: "test", Action: "test.failure",
					ActorName: "admin", Node: "NAS-A", Object: "disk3",
				}
				second := *first
				second.Node = "NAS-B"
				reg := NewRegistry(0, nil)
				created, _, _ := reg.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{first, &second}), start)
				if len(created) != 2 {
					t.Fatalf("fixture needs two independent NAS incidents: %+v", created)
				}
				reg.Persisted(created)
				if restart {
					rows := []Incident{*created[0], *created[1]}
					rows[0].Events, rows[1].Events = nil, nil
					reg = NewRegistry(2, rows)
				}
				recovery := second
				recovery.Action, recovery.TS = "test.recovery", model.FormatTS(start.Add(time.Minute))
				_, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{rule}, Events: []*model.Event{&recovery}})
				if len(closers) != 1 {
					t.Fatalf("expected one recovery: %+v", closers)
				}
				closer := closers[0]
				closed := reg.Close(closer.Rule.ID, closer.Key, "recovered", closer.Event.Time(), start.Add(2*time.Minute))
				if closed == nil || closed.Node != second.Node || closed.Status != StatusClosed {
					t.Fatalf("close_on for %q must close NAS-B, got %+v", closer.Key, closed)
				}
				for _, inc := range reg.open {
					if inc.Node == first.Node && inc.Status != StatusNew {
						t.Fatalf("recovery on NAS-B changed NAS-A: %+v", inc)
					}
				}
			})
		}
	}
}
