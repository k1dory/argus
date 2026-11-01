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

// Load the opt-in from YAML through the public directory loader. Mutating a
// compiled Rule would bypass the validation being reviewed in this PR.
func pr94ReviewMigrationRule(t *testing.T, current, previous string, threshold bool) *rules.Rule {
	t.Helper()
	dir := t.TempDir()
	yml := "title: PR94 explicit migration review\nid: pr94-migration-review\nlevel: high\ndetection:\n  selection: {action: test.failure}\n"
	if threshold {
		yml += fmt.Sprintf("  condition: selection and threshold\n  threshold:\n    kind: count\n    count: 1\n    window: 5m\n    group_by: %q\n", current)
	} else {
		yml += fmt.Sprintf("  condition: selection\n  group_by: %q\n", current)
	}
	if previous != "" {
		yml += fmt.Sprintf("  group_by_previous: %q\n", previous)
	}
	if err := os.WriteFile(filepath.Join(dir, "migration.yml"), []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != 1 || loaded[0].Detection.GroupByPrevious != previous {
		t.Fatalf("migration fixture was not loaded: %+v", loaded)
	}
	return loaded[0]
}

func pr94ReviewIncidentJSON(t *testing.T, inc *Incident) []byte {
	t.Helper()
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func pr94ReviewRestore(t *testing.T, inc *Incident) *Registry {
	t.Helper()
	var row Incident
	if err := json.Unmarshal(pr94ReviewIncidentJSON(t, inc), &row); err != nil {
		t.Fatal(err)
	}
	if row.Events != nil {
		t.Fatal("restart must discard in-memory event evidence")
	}
	return NewRegistry(1, []Incident{row})
}

// A group created under the CURRENT grouping is not a migration candidate.
// Its serialized key can equal another event's previous key, even without any
// literal delimiter. Cover both freshly created and already migrated groups;
// Persisted and a restart must not make either eligible for migration again.
func TestPR94PreviousGroupKeepsCurrentGroupsIndependent(t *testing.T) {
	for _, tc := range []struct {
		name, current, nextObject string
	}{
		{"literal_pipe", "object, attrs.detail", "resource|first"},
		{"scalar_field_replacement", "attrs.detail", "first"},
	} {
		for _, migrated := range []bool{false, true} {
			for _, restart := range []bool{false, true} {
				for _, threshold := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/migrated=%t/restart=%t/threshold=%t", tc.name, migrated, restart, threshold), func(t *testing.T) {
						current := pr94ReviewMigrationRule(t, tc.current, "object", threshold)
						seedRule := current
						if migrated {
							seedRule = pr94ReviewMigrationRule(t, "object", "", threshold)
						}
						start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
						first := &model.Event{
							TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
							ActorName: "alice", Node: "edge", Object: "resource",
							Attrs: map[string]string{"detail": "first"},
						}
						reg := NewRegistry(0, nil)
						created, _, _ := reg.Apply(eval.Run([]*rules.Rule{seedRule}, []*model.Event{first}), start)
						if len(created) != 1 {
							t.Fatalf("seed incident: %+v", created)
						}
						original := created[0]
						original.Status, original.Owner, original.Note = StatusInProgress, "reviewer", "Investigating the first resource"
						reg.Persisted(created)
						if migrated {
							created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{current}, []*model.Event{first}), start.Add(time.Minute))
							if len(created) != 0 || len(updated) != 1 || updated[0] != original {
								t.Fatalf("positive control: the old group must migrate once: created=%+v updated=%+v", created, updated)
							}
							reg.Persisted(updated)
						}
						oldKey, oldID := original.regKey(), original.IncidentID
						before := pr94ReviewIncidentJSON(t, original)
						if restart {
							reg = pr94ReviewRestore(t, original)
						}
						second := *first
						second.TS, second.Object = model.FormatTS(start.Add(2*time.Minute)), tc.nextObject
						second.Attrs = map[string]string{"detail": "second"}
						// The engine re-evaluates its retained event buffer. There is
						// no rule change between these two current-rule detections.
						dets := eval.Run([]*rules.Rule{current}, []*model.Event{first, &second})
						if len(dets) != 2 || dets[0].Key == dets[1].Key || original.GroupKey != dets[0].Key {
							t.Fatalf("fixture needs two distinct CURRENT groups: %+v", dets)
						}
						if rules.Getter("object")(&second) != original.GroupKey {
							t.Fatal("fixture must collide only with the previous-key lookup")
						}
						created, updated, _ := reg.Apply(dets, start.Add(3*time.Minute))
						if len(created) != 1 || len(updated) != 0 {
							t.Fatalf("current group %q was adopted as a legacy group: created=%+v updated=%+v; want a separate incident/notification for %q", dets[0].Key, created, updated, dets[1].Key)
						}
						if created[0].IncidentID == oldID || created[0].GroupKey != dets[1].Key || created[0].EventCount != 1 {
							t.Fatalf("second group lost its independent identity/evidence: %+v", created[0])
						}
						if after := pr94ReviewIncidentJSON(t, reg.open[oldKey]); string(after) != string(before) {
							t.Fatalf("second group changed the first incident:\nbefore: %s\nafter: %s", before, after)
						}
					})
				}
			}
		}
	}
}

// eval.groupKey uses actor.name when the configured getter returns an empty
// string. That nonempty fallback is persisted in GroupKey, so migration must
// reconstruct the same key instead of treating the old group as absent.
func TestPR94PreviousGroupReconstructsFallbackKey(t *testing.T) {
	for _, previous := range []string{"attrs.missing", "attrs.missing, attrs.also_missing"} {
		for _, threshold := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/threshold=%t", previous, threshold), func(t *testing.T) {
				oldRule := pr94ReviewMigrationRule(t, previous, "", threshold)
				current := pr94ReviewMigrationRule(t, "actor.name, attrs.detail", previous, threshold)
				start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
				event := &model.Event{
					TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
					ActorName: "alice", Node: "edge", Attrs: map[string]string{"detail": "first"},
				}
				oldDets := eval.Run([]*rules.Rule{oldRule}, []*model.Event{event})
				if len(oldDets) != 1 || oldDets[0].Key != event.ActorName || rules.Getter(previous)(event) != "" {
					t.Fatalf("fixture must use eval's nonempty fallback: %+v", oldDets)
				}
				created, _, _ := NewRegistry(0, nil).Apply(oldDets, start)
				if len(created) != 1 || created[0].GroupKey != oldDets[0].Key {
					t.Fatalf("old fallback key must be persisted: %+v", created)
				}
				original := created[0]
				original.Status, original.Owner, original.Note = StatusWaitingOwner, "reviewer", "Waiting for the resource owner"
				reg := pr94ReviewRestore(t, original)
				dets := eval.Run([]*rules.Rule{current}, []*model.Event{event})
				if len(dets) != 1 || dets[0].Key != "alice|first" {
					t.Fatalf("current grouping fixture: %+v", dets)
				}
				created, updated, _ := reg.Apply(dets, start.Add(time.Minute))
				if len(created) != 0 || len(updated) != 1 {
					t.Fatalf("explicit migration must preserve fallback-key incident %s: created=%+v updated=%+v", original.IncidentID, created, updated)
				}
				got := updated[0]
				if got.IncidentID != original.IncidentID || got.GroupKey != dets[0].Key || got.Status != original.Status || got.Owner != original.Owner || got.Note != original.Note {
					t.Fatalf("fallback-key migration lost identity or operator decisions: %+v", got)
				}
				reg.Persisted(updated)
				reg = pr94ReviewRestore(t, got)
				created, updated, _ = reg.Apply(dets, start.Add(2*time.Minute))
				if len(created)+len(updated) != 0 {
					t.Fatalf("persisted migration must be stable after restart: created=%+v updated=%+v", created, updated)
				}
			})
		}
	}
}

// The loader accepts a transition from an explicit GroupKey to a grouping
// represented entirely by ActorName/Node. The same rule, actor, node and old
// event key still match; clearing GroupKey must preserve the incident ID.
func TestPR94PreviousGroupMigratesToIdentityGrouping(t *testing.T) {
	for _, groupBy := range []string{"", "actor.name", "node", "src.ip", "dst.ip"} {
		for _, threshold := range []bool{false, true} {
			t.Run(fmt.Sprintf("group_by=%q/threshold=%t", groupBy, threshold), func(t *testing.T) {
				oldRule := pr94ReviewMigrationRule(t, "object", "", threshold)
				current := pr94ReviewMigrationRule(t, groupBy, "object", threshold)
				start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
				event := &model.Event{
					TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
					ActorName: "alice", Node: "edge", Object: "resource",
					SrcIP: "192.0.2.10", DstIP: "198.51.100.10",
				}
				// build makes the scalar address the incident actor. Preserve
				// the actor across this transition so identity is not a reason
				// to reject migration.
				if groupBy == "src.ip" {
					event.ActorName = event.SrcIP
				} else if groupBy == "dst.ip" {
					event.ActorName = event.DstIP
				}
				created, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{oldRule}, []*model.Event{event}), start)
				if len(created) != 1 || created[0].GroupKey != event.Object {
					t.Fatalf("old explicit grouping fixture: %+v", created)
				}
				original := created[0]
				original.Status, original.Owner, original.Note = StatusInProgress, "reviewer", "Existing investigation"
				reg := pr94ReviewRestore(t, original)
				dets := eval.Run([]*rules.Rule{current}, []*model.Event{event})
				if len(dets) != 1 {
					t.Fatalf("current grouping fixture: %+v", dets)
				}
				incoming := build(dets[0], start.Add(time.Minute))
				if incoming.GroupKey != "" || incoming.RuleID != original.RuleID || incoming.ActorName != original.ActorName || incoming.Node != original.Node {
					t.Fatalf("fixture must preserve rule/actor/node and drop only GroupKey: %+v", incoming)
				}
				created, updated, _ := reg.Apply(dets, start.Add(time.Minute))
				if len(created) != 0 || len(updated) != 1 {
					t.Fatalf("accepted migration to %q must continue %s: created=%+v updated=%+v", current.GroupBy(), original.IncidentID, created, updated)
				}
				got := updated[0]
				if got.IncidentID != original.IncidentID || got.GroupKey != "" || got.Status != original.Status || got.Owner != original.Owner || got.Note != original.Note {
					t.Fatalf("migration to identity grouping lost the investigation: %+v", got)
				}
				if reg.open[original.regKey()] != nil || reg.open[got.regKey()] != got {
					t.Fatal("migration must replace the old registry entry")
				}
			})
		}
	}
}

// Removing the explicit opt-in must stop adoption of a nonempty legacy key.
// This also keeps the negative branch separate from the migration fixtures.
func TestPR94PreviousGroupRequiresExplicitOptIn(t *testing.T) {
	for _, previous := range []string{"", "object"} {
		t.Run(fmt.Sprintf("previous=%q", previous), func(t *testing.T) {
			oldRule := pr94ReviewMigrationRule(t, "object", "", false)
			current := pr94ReviewMigrationRule(t, "object, attrs.detail", previous, false)
			start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
			event := &model.Event{
				TS: model.FormatTS(start), Source: "fixture", Action: "test.failure",
				ActorName: "alice", Node: "edge", Object: "resource", Attrs: map[string]string{"detail": "first"},
			}
			created, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{oldRule}, []*model.Event{event}), start)
			if len(created) != 1 {
				t.Fatalf("old incident fixture: %+v", created)
			}
			original := created[0]
			reg := pr94ReviewRestore(t, original)
			before := pr94ReviewIncidentJSON(t, reg.open[original.regKey()])
			created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{current}, []*model.Event{event}), start.Add(time.Minute))
			if previous == "" {
				if len(created) != 1 || len(updated) != 0 || created[0].IncidentID == original.IncidentID {
					t.Fatalf("absent opt-in must create an independent incident: created=%+v updated=%+v", created, updated)
				}
				if after := pr94ReviewIncidentJSON(t, reg.open[original.regKey()]); string(after) != string(before) {
					t.Fatalf("absent opt-in changed the old incident: before=%s after=%s", before, after)
				}
			} else if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != original.IncidentID {
				t.Fatalf("explicit opt-in must adopt the old incident: created=%+v updated=%+v", created, updated)
			}
		})
	}
}
