package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Field validation must inspect the mapping that the YAML decoder actually
// applies. Anchors in metadata, aliased keys and a root merge must not turn an
// unsupported detection/response option into an accepted, partial rule.
func TestPR99DeltaSchemaRejectsIndirectUnknownFields(t *testing.T) {
	const header = "title: Indirect rule\nid: pr99-indirect\nlevel: high\n"
	const detection = "detection:\n  selection: {action: test.failure}\n  condition: selection\n"
	for _, tc := range []struct {
		name, body, unknownLine, field string
	}{
		{
			name: "detection_alias",
			body: "notes: &detection_options\n" +
				"  selection: {action: test.failure}\n  group_by: attrs.peer\n  group_by_next: attrs.peer\n" +
				"detection: *detection_options\n",
			unknownLine: "  group_by_next: attrs.peer\n", field: "group_by_next",
		},
		{
			name: "threshold_alias",
			body: "notes: &threshold_options\n  count: 2\n  window: 5m\n  kind_next: consecutive\n" +
				"detection:\n  selection: {action: test.failure}\n  condition: selection and threshold\n  threshold: *threshold_options\n",
			unknownLine: "  kind_next: consecutive\n", field: "kind_next",
		},
		{
			name: "respond_alias",
			body: "notes: &response_options\n  action: block_ip\n  min_events_next: 10\n" +
				detection + "respond: *response_options\n",
			unknownLine: "  min_events_next: 10\n", field: "min_events_next",
		},
		{
			name: "analyst_alias",
			body: "notes: &analyst_options\n  profile: mock\n  mode_next: private\n" +
				detection + "analyst: *analyst_options\n",
			unknownLine: "  mode_next: private\n", field: "mode_next",
		},
		{
			name: "root_merge",
			body: "<<:\n  detection:\n    selection: {action: test.failure}\n" +
				"    group_by: attrs.peer\n    group_by_next: attrs.peer\n",
			unknownLine: "    group_by_next: attrs.peer\n", field: "group_by_next",
		},
		{
			name: "aliased_detection_key",
			body: "notes: &section_name detection\n*section_name:\n" +
				"  selection: {action: test.failure}\n  group_by: attrs.peer\n  group_by_next: attrs.peer\n",
			unknownLine: "  group_by_next: attrs.peer\n", field: "group_by_next",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "indirect.yml")
			write := func(raw string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			// Positive control: the same YAML structure, using only supported
			// options, is valid and still matches the intended event.
			write(header + strings.Replace(tc.body, tc.unknownLine, "", 1))
			control, err := LoadFile(path)
			if err != nil || !control.Match(&model.Event{Action: "test.failure"}) {
				t.Fatalf("supported YAML indirection must work: rule=%+v err=%v", control, err)
			}

			write(header + tc.body)
			if loaded, err := LoadFile(path); err == nil {
				t.Errorf("LoadFile silently accepted unsupported %s: id=%q group_by=%q", tc.field, loaded.ID, loaded.GroupBy())
			} else if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("rejection must identify %s: %v", tc.field, err)
			}
			good := "title: Unrelated rule\nid: pr99-unrelated\n" + detection
			if err := os.WriteFile(filepath.Join(dir, "good.yml"), []byte(good), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, rejected, err := LoadAll(dir)
			if err != nil || len(loaded) != 1 || loaded[0].ID != "pr99-unrelated" || len(rejected) != 1 || rejected[0].File != "indirect.yml" {
				t.Errorf("LoadAll must isolate the unsupported rule: loaded=%d rejected=%+v err=%v", len(loaded), rejected, err)
			}
			if _, err := Load(dir); err == nil {
				t.Error("strict CLI Load also accepted the unsupported rule")
			}
		})
	}
}
