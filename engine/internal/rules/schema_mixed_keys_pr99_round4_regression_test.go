package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// yaml.v3 decodes an interface-valued mapping with a non-string key as
// map[interface{}]interface{}. It can still decode that mapping into a struct,
// ignoring unknown keys. The schema check must not skip such a whole section.
func TestPR99Round4SchemaRejectsMixedKeyUnknownFields(t *testing.T) {
	const header = "title: Mixed keys\nid: pr99-round4-mixed\nlevel: high\n"
	const selection = "detection:\n  selection: {action: test.failure}\n"
	for _, tc := range []struct {
		name, body, unknown, nonStringKey string
	}{
		{
			name:    "detection",
			body:    selection + "  group_by: attrs.peer\n  group_by_next: attrs.peer\n  7: ignored\n",
			unknown: "  group_by_next: attrs.peer\n", nonStringKey: "  7: ignored\n",
		},
		{
			name: "detection_alias",
			body: "notes: &options\n  selection: {action: test.failure}\n" +
				"  group_by_next: attrs.peer\n  7: ignored\ndetection: *options\n",
			unknown: "  group_by_next: attrs.peer\n", nonStringKey: "  7: ignored\n",
		},
		{
			name: "detection_merge",
			body: "detection:\n  <<:\n    selection: {action: test.failure}\n" +
				"    group_by_next: attrs.peer\n  7: ignored\n",
			unknown: "    group_by_next: attrs.peer\n", nonStringKey: "  7: ignored\n",
		},
		{
			name: "threshold",
			body: selection + "  condition: selection and threshold\n  threshold:\n" +
				"    count: 2\n    window: 5m\n    kind_next: consecutive\n    7: ignored\n",
			unknown: "    kind_next: consecutive\n", nonStringKey: "    7: ignored\n",
		},
		{
			name:    "respond",
			body:    selection + "respond:\n  action: block_ip\n  min_events_next: 10\n  7: ignored\n",
			unknown: "  min_events_next: 10\n", nonStringKey: "  7: ignored\n",
		},
		{
			name:    "analyst",
			body:    selection + "analyst:\n  profile: mock\n  mode_next: private\n  7: ignored\n",
			unknown: "  mode_next: private\n", nonStringKey: "  7: ignored\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "mixed.yml")
			write := func(raw string) {
				t.Helper()
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			// Both the supported structure and rejection of the same unknown
			// option without the extra numeric key are positive controls.
			withoutNumeric := strings.Replace(tc.body, tc.nonStringKey, "", 1)
			write(header + strings.Replace(withoutNumeric, tc.unknown, "", 1))
			control, err := LoadFile(path)
			if err != nil || !control.Match(&model.Event{Action: "test.failure"}) {
				t.Fatalf("supported control: rule=%+v err=%v", control, err)
			}
			write(header + withoutNumeric)
			if _, err := LoadFile(path); err == nil {
				t.Fatal("control must reject the unknown option without a numeric key")
			}

			write(header + tc.body)
			if got, err := LoadFile(path); err == nil {
				t.Errorf("numeric key bypassed schema validation: id=%s group_by=%q respond_min_events=%d", got.ID, got.GroupBy(), got.RespondMinEvents())
			}
			good := "title: Unrelated\nid: pr99-round4-unrelated\ndetection:\n  selection: {action: other.event}\n"
			if err := os.WriteFile(filepath.Join(dir, "good.yml"), []byte(good), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, rejected, err := LoadAll(dir)
			if err != nil || len(loaded) != 1 || loaded[0].ID != "pr99-round4-unrelated" || len(rejected) != 1 || rejected[0].File != "mixed.yml" {
				t.Errorf("partial detector must be rejected in isolation: loaded=%d rejected=%+v err=%v", len(loaded), rejected, err)
			}
		})
	}
}
