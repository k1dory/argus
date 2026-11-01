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

// A literal pipe in an event value is not a change to the rule's group_by.
// These shipped rules already produce distinct detections before Apply. The
// new prefix adoption must not consume their second incident/notification.
func TestPR94WidenedGroupKeepsLiteralPipeValuesIndependent(t *testing.T) {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, family := range []string{"security_scalar", "ops_composite", "backslash_in_value"} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/restart=%t", family, restart), func(t *testing.T) {
				var rule *rules.Rule
				var first, second []*model.Event
				switch family {
				case "security_scalar":
					var err error
					rule, err = rules.LoadFile("../../../rules/wazuh/sudoers-change.yml")
					if err != nil {
						t.Fatal(err)
					}
					// Reach the real distinct-host threshold twice, for two
					// different filenames. Both paths are legal on Unix.
					for i := 0; i < 5; i++ {
						e := &model.Event{
							TS:     model.FormatTS(start.Add(time.Duration(i) * time.Second)),
							Source: "wazuh.agents", Action: "file.modified",
							ActorName: "root", Node: fmt.Sprintf("host-%d", i), Object: "/etc/sudoers",
						}
						other := *e
						other.TS = model.FormatTS(start.Add(time.Duration(i+10) * time.Second))
						other.Object = "/etc/sudoers|fixture"
						first, second = append(first, e), append(second, &other)
					}
				case "ops_composite":
					rule = qnapStorageRule(t)
					e := qnapStorageEvent("NAS-A", 3, 0)
					e.TS = model.FormatTS(start)
					other := *e
					other.TS = model.FormatTS(start.Add(time.Second))
					other.Object += "|another storage fault"
					first, second = []*model.Event{e}, []*model.Event{&other}
				case "backslash_in_value":
					rule = compositeRegressionRule(t, "object", false)
					e := &model.Event{
						TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
						ActorName: "operator", Node: "NAS-A", Object: `resource\`,
					}
					other := *e
					other.TS = model.FormatTS(start.Add(time.Second))
					other.Object = `resource\|other`
					first, second = []*model.Event{e}, []*model.Event{&other}
				}
				pr94AssertIndependentValueGroups(t, rule, first, second, restart)
			})
		}
	}
}

func pr94AssertIndependentValueGroups(t *testing.T, rule *rules.Rule, first, second []*model.Event, restart bool) {
	t.Helper()
	reg := NewRegistry(0, nil)
	dets := eval.Run([]*rules.Rule{rule}, first)
	if len(dets) != 1 {
		t.Fatalf("first fixture must reach the rule threshold once: %+v", dets)
	}
	now := second[len(second)-1].Time().Add(time.Minute)
	created, _, _ := reg.Apply(dets, now)
	if len(created) != 1 {
		t.Fatalf("first fixture incident: %+v", created)
	}
	original := created[0]
	original.Status, original.Owner, original.Note = StatusInProgress, "fixture-reviewer", "Investigating the first resource"
	reg.Persisted(created)
	oldKey, oldID := original.regKey(), original.IncidentID
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if restart {
		var persisted Incident
		if err := json.Unmarshal(before, &persisted); err != nil {
			t.Fatal(err)
		}
		if persisted.Events != nil {
			t.Fatal("restart must discard in-memory evidence")
		}
		reg = NewRegistry(1, []Incident{persisted})
	}

	// Mirror the engine's next evaluation of its retained buffer. There is no
	// rule reload, schema change or ambiguous equal key in this reproduction.
	events := append(append([]*model.Event{}, first...), second...)
	dets = eval.Run([]*rules.Rule{rule}, events)
	if len(dets) != 2 || dets[0].Key == dets[1].Key {
		t.Fatalf("fixture must produce independent detections: %+v", dets)
	}
	created, updated, _ := reg.Apply(dets, now.Add(time.Minute))
	if len(created) != 1 || len(updated) != 0 {
		t.Fatalf("unchanged rule %s (%s): literal pipe merged distinct keys %q and %q; created=%d updated=%d, want one new incident and no update to %s",
			rule.ID, rule.GroupBy(), dets[0].Key, dets[1].Key, len(created), len(updated), oldID)
	}
	if created[0].IncidentID == oldID || created[0].GroupKey != dets[1].Key || created[0].EventCount != uint32(len(second)) {
		t.Fatalf("second resource needs its own identity and evidence: %+v", created[0])
	}
	after, err := json.Marshal(reg.open[oldKey])
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("second resource changed the first incident:\nbefore: %s\nafter:  %s", before, after)
	}
}
