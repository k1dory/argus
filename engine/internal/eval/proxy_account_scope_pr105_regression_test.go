package eval_test

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Independent published services can have identically named local accounts.
// Activity by portal-b/admin must create its own incident even while the
// window still contains portal-a/admin. The registry's node key cannot repair
// an evaluator group that has already pooled both services under "admin".
func TestPR105ForeignAccountKeepsServiceAccountsSeparate(t *testing.T) {
	account, err := rules.LoadFile("../../../rules/proxy-foreign-account.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, secondNode, secondActor string
		wantDetections, wantNew       int
	}{
		{"independent local admin accounts", "portal-b.example", "admin", 2, 1},
		{"same service and account control", "portal-a.example", "admin", 1, 0},
		{"different account control", "portal-a.example", "alice", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			event := func(at time.Time, node, actor, src string) *model.Event {
				return &model.Event{
					TS: model.FormatTS(at), Source: "proxy.fixture", SourceClass: "proxy",
					Action: "proxy.access", Outcome: "success", ActorKind: "user", ActorName: actor,
					Node: node, SrcIP: src, Object: node + "/account",
					Attrs: map[string]string{"country": "DE", "status": "200"},
				}
			}
			first := event(start, "portal-a.example", "admin", "198.51.100.41")
			second := event(start.Add(time.Minute), tc.secondNode, tc.secondActor, "198.51.100.42")
			registry := incidents.NewRegistry(105000, nil)
			created, _, dropped := registry.Apply(eval.Run([]*rules.Rule{account}, []*model.Event{first}), start)
			if len(created) != 1 || len(dropped) != 0 || created[0].Node != first.Node || created[0].ActorName != first.ActorName {
				t.Fatalf("first access must create its service/account incident: created=%+v dropped=%v", created, dropped)
			}

			detections := eval.Run([]*rules.Rule{account}, []*model.Event{first, second})
			if len(detections) != tc.wantDetections {
				t.Errorf("two accesses to %s/%s and %s/%s produced %d detections, want %d",
					first.Node, first.ActorName, second.Node, second.ActorName, len(detections), tc.wantDetections)
			}
			for _, detection := range detections {
				for _, e := range detection.Events {
					if e.Node != detection.Events[0].Node || e.ActorName != detection.Events[0].ActorName {
						t.Errorf("one account detection pooled independent service identities: %+v", detection)
					}
				}
			}
			created, updated, dropped := registry.Apply(detections, second.Time())
			if len(created) != tc.wantNew || len(dropped) != 0 {
				t.Fatalf("second access created=%d updated=%d dropped=%v; want %d new service/account incident(s)", len(created), len(updated), dropped, tc.wantNew)
			}
			if tc.wantNew == 1 && (created[0].Node != second.Node || created[0].ActorName != second.ActorName || created[0].EventCount != 1) {
				t.Errorf("second incident has the wrong service/account/evidence: %+v", created[0])
			}
			if tc.wantNew == 0 && (len(updated) != 1 || updated[0].EventCount != 2) {
				t.Errorf("same service/account should retain both events in one updated incident: %+v", updated)
			}
		})
	}
}
