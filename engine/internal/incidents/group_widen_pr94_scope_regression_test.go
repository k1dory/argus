package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// The serialized base is not an identity check: pipes in rule IDs, actor names
// and nodes are accepted by the model/loader. These old and new full registry
// keys are different; only PR94's prefix fallback makes them collide.
func TestPR94WidenedGroupChecksStructuredIdentity(t *testing.T) {
	type identity struct{ rule, actor, node string }
	ordinary := identity{"pr94-scope", "alice", "edge"}
	for _, tc := range []struct {
		name      string
		old, next identity
		wantAdopt bool
		baseClash bool
	}{
		{"same identity control", ordinary, ordinary, true, true},
		{"different rule control", ordinary, identity{"pr94-other", "alice", "edge"}, false, false},
		{"different actor control", ordinary, identity{"pr94-scope", "bob", "edge"}, false, false},
		{"different node control", ordinary, identity{"pr94-scope", "alice", "other"}, false, false},
		{"actor-node delimiter collision", identity{"pr94-scope", "alice|edge", "one"}, identity{"pr94-scope", "alice", "edge|one"}, false, true},
		{"rule-actor delimiter collision", identity{"pr94-scope|realm", "alice", "edge"}, identity{"pr94-scope", "realm|alice", "edge"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldRule := compositeRegressionRule(t, "object", false)
			newRule := compositeRegressionRule(t, "object, attrs.detail", false)
			oldRule.ID, newRule.ID = tc.old.rule, tc.next.rule
			start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
			first := &model.Event{
				TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
				ActorName: tc.old.actor, Node: tc.old.node, Object: "resource",
				Attrs: map[string]string{"detail": "scope"},
			}
			created, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{oldRule}, []*model.Event{first}), start)
			if len(created) != 1 {
				t.Fatalf("old incident fixture: %+v", created)
			}
			old := *created[0]
			old.Events = nil
			old.Status, old.Owner, old.Note = StatusInProgress, "first-principal-reviewer", "Only the original principal was reviewed"
			reg := NewRegistry(1, []Incident{old})
			next := *first
			next.TS = model.FormatTS(start.Add(time.Minute))
			next.ActorName, next.Node = tc.next.actor, tc.next.node
			dets := eval.Run([]*rules.Rule{newRule}, []*model.Event{&next})
			if len(dets) != 1 {
				t.Fatalf("next detection fixture: %+v", dets)
			}
			incoming := build(dets[0], start.Add(2*time.Minute))
			if incoming.regKey() == old.regKey() {
				t.Fatal("fixture must not rely on a pre-existing exact registry-key collision")
			}
			base := func(i identity) string { return i.rule + "|" + i.actor + "|" + i.node }
			if (base(tc.old) == base(tc.next)) != tc.baseClash {
				t.Fatal("incorrect base collision fixture")
			}

			created, updated, _ := reg.Apply(dets, start.Add(2*time.Minute))
			if tc.wantAdopt {
				if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != old.IncidentID || updated[0].GroupKey != dets[0].Key {
					t.Fatalf("same-principal widening must preserve identity: created=%+v updated=%+v", created, updated)
				}
				return
			}
			if len(created) != 1 || len(updated) != 0 {
				t.Fatalf("widening crossed an identity boundary: old=%+v next=%+v; created=%d updated=%d; want an independent incident, not %s",
					tc.old, tc.next, len(created), len(updated), old.IncidentID)
			}
			if created[0].IncidentID == old.IncidentID || created[0].RuleID != tc.next.rule || created[0].ActorName != tc.next.actor || created[0].Node != tc.next.node {
				t.Fatalf("new principal received the old principal's identity: %+v", created[0])
			}
			if got := reg.open[old.regKey()]; got == nil || got.GroupKey != old.GroupKey || got.LastTS != old.LastTS || got.Owner != old.Owner || got.Note != old.Note {
				t.Fatalf("foreign principal changed the old incident: %+v", got)
			}
		})
	}
}
