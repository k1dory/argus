package incidents

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// c4a9b92 already persisted a nonempty group_key (the peer). Restoring an
// incident created by that rule is different from restarting PR88 itself or
// adopting an incident created before the group_key column existed.
func TestPR88ClockSkewUpgradeKeepsExistingIncident(t *testing.T) {
	rule, fixture := pr80ClockSkewFixture(t)
	legacyRule := *rule
	legacyRule.Detection.GroupBy = "attrs.peer"
	first := fixture[0]
	now := first.Time().Add(time.Minute)

	for _, status := range []string{StatusNew, StatusInProgress} {
		t.Run(status, func(t *testing.T) {
			created, _, _ := NewRegistry(0, nil).Apply(
				eval.Run([]*rules.Rule{&legacyRule}, []*model.Event{first}), now)
			if len(created) != 1 || created[0].GroupKey != first.Attrs["peer"] {
				t.Fatalf("pre-PR88 rule must persist the peer as group_key: %+v", created)
			}
			created[0].Status = status
			created[0].Owner = "clock-reviewer"
			created[0].Note = "Source timezone is being corrected"
			oldID := created[0].IncidentID

			// Events are json:"-": the restart has precisely the persisted
			// incident fields, including the pre-PR88 nonempty group_key.
			raw, err := json.Marshal(created)
			if err != nil {
				t.Fatal(err)
			}
			var persisted []Incident
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted[0].Events != nil {
				t.Fatal("restart fixture must not retain in-memory evidence")
			}
			registry := NewRegistry(1, persisted)
			detections := eval.Run([]*rules.Rule{rule}, []*model.Event{first})
			created, updated, _ := registry.Apply(detections, now.Add(time.Minute))
			if len(created) != 0 || len(updated) != 1 {
				t.Fatalf("upgrading the same clock-skew evidence must migrate %s, not create a second open incident: created=%d updated=%d old_group=%q new_group=%q",
					oldID, len(created), len(updated), persisted[0].GroupKey, detections[0].Key)
			}
			migrated := updated[0]
			if migrated.IncidentID != oldID || migrated.GroupKey != detections[0].Key ||
				migrated.Status != status || migrated.Owner != persisted[0].Owner || migrated.Note != persisted[0].Note {
				t.Fatalf("migration must preserve incident identity and operator decisions: %+v", migrated)
			}
			registry.Persisted(updated)

			// New evidence for the same source still belongs to that incident.
			next := *first
			next.TS = model.FormatTS(now.Add(2 * time.Minute))
			created, updated, _ = registry.Apply(
				eval.Run([]*rules.Rule{rule}, []*model.Event{first, &next}), now.Add(3*time.Minute))
			if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != oldID {
				t.Fatalf("new evidence after migration must update %s: created=%d updated=%d", oldID, len(created), len(updated))
			}
		})
	}
}
