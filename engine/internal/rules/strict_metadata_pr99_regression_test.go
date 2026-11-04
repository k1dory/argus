package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Metadata did not affect matching before PR99. Rejecting it on upgrade also
// rejects unrelated rules in Load; engine run calls mustLoad before starting
// the HTTP server, so its in-memory reload fallback cannot preserve detection.
// Keep an explicit metadata allowlist while still rejecting unknown operational
// fields (covered by TestLoadRejectsUnknownFields).
func TestPR99UpgradePreservesRuleMetadataCompatibility(t *testing.T) {
	const custom = "title: Custom login detection\nid: pr99-custom\nlevel: high\ndetection:\n  selection: {action: login.fail}\n  condition: selection\n  group_by: actor.name\n"
	const builtin = "title: Unrelated detection\nid: pr99-builtin\ndetection:\n  selection: {action: process.start}\n"
	for _, tc := range []struct {
		name, metadata string
	}{
		{"description", "description: Local rule maintained by the SOC\n"},
		{"author", "author: Local SOC\n"},
		{"references", "references: [https://example.invalid/runbook]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(custom + tc.metadata)
			// Positive control for the parser used at ef8dc67: the custom
			// file was valid, and its detection fields were not discarded.
			var previous Rule
			if err := yaml.Unmarshal(raw, &previous); err != nil {
				t.Fatalf("pre-upgrade parser rejected the fixture: %v", err)
			}
			var err error
			previous.selection, err = compile(previous.Detection.Selection)
			if err != nil || previous.ID != "pr99-custom" || previous.GroupBy() != "actor.name" {
				t.Fatalf("invalid pre-upgrade fixture: rule=%+v err=%v", previous, err)
			}
			event := &model.Event{Action: "login.fail", ActorName: "alice"}
			if !previous.Match(event) {
				t.Fatal("pre-upgrade rule must detect the fixture")
			}

			dir := t.TempDir()
			for name, data := range map[string][]byte{"a-builtin.yml": []byte(builtin), "b-custom.yml": raw} {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			loaded, err := Load(dir)
			if err != nil {
				if !strings.Contains(err.Error(), "b-custom.yml") || !strings.Contains(err.Error(), tc.name) {
					t.Fatalf("unexpected failure, not the metadata compatibility defect: %v", err)
				}
				t.Fatalf("upgrade rejects a previously valid metadata field and the entire rule set (loaded=%d): %v", len(loaded), err)
			}
			if len(loaded) != 2 || loaded[1].ID != previous.ID || !loaded[1].Match(event) {
				t.Fatalf("upgrade changed detection or lost an unrelated rule: %+v", loaded)
			}
		})
	}
}
