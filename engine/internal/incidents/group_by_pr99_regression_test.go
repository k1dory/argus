package incidents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr99MigrationRule(t *testing.T, current, previous, before string) *rules.Rule {
	t.Helper()
	yml := fmt.Sprintf("title: PR99 migration\nid: pr99-migration\nlevel: high\ndetection:\n  selection: {action: test.failure}\n  condition: selection\n  group_by: %q\n", current)
	if previous != "" {
		yml += fmt.Sprintf("  group_by_previous: %q\n", previous)
	}
	if before != "" {
		yml += fmt.Sprintf("  group_by_previous_before: %q\n", before)
	}
	path := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(path, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	rule, err := rules.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func pr99RestoreIncident(t *testing.T, inc *Incident) *Registry {
	t.Helper()
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	var row Incident
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	return NewRegistry(1, []Incident{row})
}

// A migration may change the field but not its value for the first event. Once
// that event has been evaluated under the new grouping, the incident belongs to
// the new group even when neither group_key nor event_count changes. Otherwise a
// later sibling adopts it again and loses its independent incident/notification.
func TestPR99SameKeyMigrationCannotBeAdoptedAgain(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		for _, restart := range []bool{false, true} {
			t.Run(fmt.Sprintf("pre0039=%t/restart=%t", legacy, restart), func(t *testing.T) {
				start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
				oldRule := pr99MigrationRule(t, "object", "", "")
				current := pr99MigrationRule(t, "attrs.detail", "object", "2026-11-01 12:00:30")
				first := &model.Event{
					TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
					ActorName: "alice", Node: "edge", Object: "resource-a",
					Attrs: map[string]string{"detail": "resource-a"},
				}
				reg := NewRegistry(0, nil)
				created, _, _ := reg.Apply(eval.Run([]*rules.Rule{oldRule}, []*model.Event{first}), start)
				if len(created) != 1 || created[0].GroupKey != "resource-a" {
					t.Fatalf("invalid old grouping fixture: %+v", created)
				}
				original := created[0]
				original.Status, original.Owner, original.Note = StatusInProgress, "reviewer", "Investigating resource-a"
				if legacy {
					original.GroupBy = "" // Persisted row predating migration 0039.
				}
				reg = pr99RestoreIncident(t, original)
				original = reg.open[original.regKey()]
				originalKey, originalID := original.regKey(), original.IncidentID

				created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{current}, []*model.Event{first}), start.Add(time.Minute))
				if len(created) != 0 {
					t.Fatalf("same-key migration must preserve the original incident: %+v", created)
				}
				if original.GroupBy != current.GroupBy() || len(updated) != 1 {
					t.Errorf("same-key migration must persist current group_by even without new evidence: group_by=%q, updated=%d", original.GroupBy, len(updated))
				}
				reg.Persisted(updated)
				if restart {
					reg = pr99RestoreIncident(t, original)
				}

				second := *first
				second.TS = model.FormatTS(start.Add(2 * time.Minute))
				second.Attrs = map[string]string{"detail": "resource-b"}
				dets := eval.Run([]*rules.Rule{current}, []*model.Event{first, &second})
				if len(dets) != 2 || dets[0].Key == dets[1].Key {
					t.Fatalf("fixture needs two independent current groups: %+v", dets)
				}
				created, updated, _ = reg.Apply(dets, start.Add(3*time.Minute))
				if len(created) != 1 || len(updated) != 0 {
					t.Fatalf("resource-b adopted the already-current resource-a incident: created=%d updated=%d; want one new incident/notification", len(created), len(updated))
				}
				if created[0].IncidentID == originalID || created[0].GroupKey != "resource-b" {
					t.Fatalf("sibling lost its independent identity: %+v", created[0])
				}
				kept := reg.open[originalKey]
				if kept == nil || kept.GroupKey != "resource-a" || kept.GroupBy != current.GroupBy() || kept.Status != StatusInProgress || kept.Owner != "reviewer" || kept.Note != "Investigating resource-a" {
					t.Fatalf("sibling changed the first investigation: %+v", kept)
				}
			})
		}
	}
}

// An empty group_key is not proof that a row predates group_key/group_by:
// identity groupings and the literal '-' also produce it today. The legacy
// shortcut must enforce the same provenance/cutoff as previousGroup.
func TestPR99EmptyGroupKeyStillRequiresMigrationProvenance(t *testing.T) {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, seedGroup, before string
		legacy                  bool
		created                 time.Time
		adopt                   bool
	}{
		{"current_group", "object", "", false, start, false},
		{"different_previous_group", "node", "", false, start, false},
		{"known_previous_control", "actor.name", "", false, start, true},
		{"legacy_without_cutoff", "actor.name", "", true, start.Add(-time.Minute), false},
		{"legacy_at_cutoff", "actor.name", "2026-11-01 12:00:00", true, start, false},
		{"legacy_after_cutoff", "actor.name", "2026-11-01 12:00:00", true, start.Add(time.Minute), false},
		{"legacy_before_cutoff_control", "actor.name", "2026-11-01 12:00:00", true, start.Add(-time.Minute), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seedRule := pr99MigrationRule(t, tc.seedGroup, "", "")
			current := pr99MigrationRule(t, "object", "actor.name", tc.before)
			first := &model.Event{
				TS: model.FormatTS(tc.created), Source: "fixture", Action: "test.failure",
				ActorName: "alice", Node: "edge", Object: "-",
			}
			created, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{seedRule}, []*model.Event{first}), tc.created)
			if len(created) != 1 || created[0].GroupKey != "" || created[0].GroupBy != tc.seedGroup {
				t.Fatalf("fixture needs a real empty-key incident: %+v", created)
			}
			original := created[0]
			original.Status, original.Owner, original.Note = StatusWaitingOwner, "reviewer", "Existing investigation"
			if tc.legacy {
				original.GroupBy = ""
			}
			before, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			reg := pr99RestoreIncident(t, original)
			second := *first
			second.TS, second.Object = model.FormatTS(start.Add(2*time.Minute)), "resource-b"
			created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{current}, []*model.Event{&second}), start.Add(3*time.Minute))
			if tc.adopt {
				if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != original.IncidentID || updated[0].GroupBy != "object" || updated[0].GroupKey != "resource-b" {
					t.Fatalf("eligible previous group must migrate: created=%+v updated=%+v", created, updated)
				}
				return
			}
			if len(created) != 1 || len(updated) != 0 || created[0].IncidentID == original.IncidentID {
				t.Fatalf("empty-key shortcut bypassed group_by/cutoff: old group_by=%q created_at=%q; created=%d updated=%d", original.GroupBy, original.CreatedAt, len(created), len(updated))
			}
			after, err := json.Marshal(reg.open[original.regKey()])
			if err != nil || string(after) != string(before) {
				t.Fatalf("ineligible incident was mutated: before=%s after=%s err=%v", before, after, err)
			}
		})
	}
}
