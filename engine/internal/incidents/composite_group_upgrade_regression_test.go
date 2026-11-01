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

// Positive upgrade control for the shipped actor.name,node rule: its open
// incidents at 0e35e34 have no group_key. Adopting the new composite key must
// preserve both incident identities and operator decisions across a restart.
func TestPR21NASCompositeUpgradePreservesExistingIncidents(t *testing.T) {
	rule, err := rules.LoadFile("../../../rules/nas-mass-file-change.yml")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	var events []*model.Event
	for _, node := range []string{"NAS-A", "NAS-B"} {
		for n := 0; n < 200; n++ {
			events = append(events, &model.Event{
				TS:     model.FormatTS(start.Add(time.Duration(n) * time.Second)),
				Source: "nas.qnap", Action: "file.delete", ActorName: "admin", Node: node,
				Object: fmt.Sprintf("Public/report-%d.txt", n),
			})
		}
	}
	dets := eval.Run([]*rules.Rule{rule}, events)
	if len(dets) != 2 {
		t.Fatalf("fixture must reach the threshold separately on each NAS: detections=%d", len(dets))
	}
	var legacy []Incident
	wantID := make(map[string]string)
	for n, node := range []string{"NAS-A", "NAS-B"} {
		id := fmt.Sprintf("INC-%d", n+7)
		wantID[node] = id
		legacy = append(legacy, Incident{
			IncidentID: id, RuleID: rule.ID, RuleTitle: rule.Title, Level: rule.Level,
			ActorName: "admin", Node: node, Status: StatusInProgress,
			Owner: "analyst-" + node, Note: "Investigating " + node, EventCount: 200,
			FirstTS: model.FormatTS(start), LastTS: model.FormatTS(start.Add(199 * time.Second)),
			CreatedAt: model.FormatTS(start)[:19], UpdatedAt: model.FormatTS(start.Add(4 * time.Minute))[:19],
		})
	}
	reg := NewRegistry(8, legacy)
	created, updated, _ := reg.Apply(dets, start.Add(5*time.Minute))
	if len(created) != 0 || len(updated) != 2 {
		t.Fatalf("software upgrade must adopt both legacy incidents without notifications: created=%d updated=%d", len(created), len(updated))
	}
	for _, inc := range updated {
		if inc.IncidentID != wantID[inc.Node] || inc.GroupKey != "admin|"+inc.Node {
			t.Fatalf("upgrade changed incident identity or NAS group: %+v", inc)
		}
		if inc.Status != StatusInProgress || inc.Owner != "analyst-"+inc.Node || inc.Note != "Investigating "+inc.Node {
			t.Fatalf("upgrade lost the operator's investigation: %+v", inc)
		}
	}
	reg.Persisted(updated)
	raw, err := json.Marshal(updated)
	if err != nil {
		t.Fatal(err)
	}
	var restored []Incident
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	reg = NewRegistry(8, restored)
	created, updated, _ = reg.Apply(dets, start.Add(6*time.Minute))
	if len(created) != 0 || len(updated) != 0 {
		t.Fatalf("replay after upgrade and restart must not split or rewrite incidents: created=%d updated=%d", len(created), len(updated))
	}
	created, updated, _ = reg.Apply(nil, start.Add(25*time.Hour))
	if len(created) != 0 || len(updated) != 0 {
		t.Fatalf("persisted migration must stay settled after the event buffer expires: created=%d updated=%d", len(created), len(updated))
	}
}
