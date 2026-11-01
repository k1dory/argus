package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// PR #72 / merge #73: the shipped registry includes both rules and fixture
// metadata. A rules-only bundle must not silently turn fixture-only sources
// and actions into [source]/[action] in an otherwise successful dataset export.
func TestPR72RegistryRejectsMissingFixtures(t *testing.T) {
	previous := current.Load()
	t.Cleanup(func() { current.Store(previous) })

	for _, missingDirectory := range []bool{false, true} {
		name := "empty_directory"
		if missingDirectory {
			name = "missing_directory"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			rulesDir := filepath.Join(dir, "rules")
			fixturesDir := filepath.Join(dir, "fixtures")
			for _, p := range []string{rulesDir, fixturesDir} {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			rule := "id: pr72-shipped\ntitle: Shipped rule\nlevel: high\ndetection:\n  selection:\n    source: host.sshd\n    action: auth.ssh\n  condition: selection\n"
			if err := os.WriteFile(filepath.Join(rulesDir, "rule.yml"), []byte(rule), 0o600); err != nil {
				t.Fatal(err)
			}
			fixturePath := filepath.Join(fixturesDir, "events.ndjson")
			if err := os.WriteFile(fixturePath, []byte("{\"source\":\"edr.kaspersky\",\"action\":\"file.read\"}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Load(dir); err != nil {
				t.Fatalf("complete bundle: %v", err)
			}
			if !Loaded() || !Source("host.sshd") || !Action("auth.ssh") || !Source("edr.kaspersky") || !Action("file.read") {
				t.Fatal("complete bundle must recognize metadata from both rules and fixtures")
			}

			if err := os.Remove(fixturePath); err != nil {
				t.Fatal(err)
			}
			if missingDirectory {
				if err := os.Remove(fixturesDir); err != nil {
					t.Fatal(err)
				}
			}
			if err := Load(dir); err == nil {
				t.Fatal("incomplete shipped bundle accepted: rule metadata masks missing fixtures, so dataset export silently loses fixture-only sources/actions")
			}
			if !Source("edr.kaspersky") || !Action("file.read") {
				t.Fatal("a failed reload must preserve the complete registry")
			}
		})
	}
}
