package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// A YAML merge is syntax, not an unknown engine option. These rules contain
// only known fields and pass the strict decoder at 3744f06. Rejecting them in
// LoadAll silently removes their detection from the startup rule set.
func TestPR99DeltaSchemaPreservesSupportedNestedMerges(t *testing.T) {
	const header = "title: Merged rule\nid: pr99-merged\nlevel: high\n"
	const selection = "detection:\n  selection: {action: test.failure}\n"
	for _, tc := range []struct{ name, body string }{
		{"detection", "detection:\n  <<: {selection: {action: test.failure}, condition: selection}\n  group_by: actor.name\n"},
		{"threshold", selection + "  condition: selection and threshold\n  threshold:\n    <<: {count: 2, window: 5m}\n    group_by: actor.name\n"},
		{"respond", selection + "respond:\n  <<: {action: block_ip, ttl: 1h}\n  min_events: 2\n"},
		{"analyst", selection + "analyst:\n  <<: {profile: mock}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := header + tc.body
			// Keep a positive control for the parser in the requested base
			// revision; no permissive metadata decoding is involved here.
			var previous Rule
			decoder := yaml.NewDecoder(strings.NewReader(raw))
			decoder.KnownFields(true)
			if err := decoder.Decode(&previous); err != nil {
				t.Fatalf("base-revision strict decoder rejected the control: %v", err)
			}
			var err error
			previous.selection, err = compile(previous.Detection.Selection)
			event := &model.Event{Action: "test.failure", ActorName: "alice"}
			if err != nil || previous.ID != "pr99-merged" || !previous.Match(event) {
				t.Fatalf("invalid pre-upgrade detection: rule=%+v err=%v", previous, err)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "merged.yml")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if rule, err := LoadFile(path); err != nil || !rule.Match(event) {
				t.Errorf("previously supported merge must retain its detection: rule=%+v err=%v", rule, err)
			}
			good := "title: Unrelated rule\nid: pr99-unrelated\ndetection:\n  selection: {action: other.event}\n"
			if err := os.WriteFile(filepath.Join(dir, "good.yml"), []byte(good), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, rejected, err := LoadAll(dir)
			if err != nil || len(rejected) != 0 || len(loaded) != 2 {
				t.Errorf("startup would lose a valid detector: loaded=%d rejected=%+v err=%v", len(loaded), rejected, err)
			}
			if _, err := Load(dir); err != nil {
				t.Errorf("strict CLI Load must accept these supported fields: %v", err)
			}
		})
	}
}
