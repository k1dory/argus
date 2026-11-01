package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// PR #73: rule selectors alone must not make a missing fixture bundle look
// complete. Fixture-only vocabulary (for example edr.kaspersky/file.read)
// would otherwise silently disappear from exported decision states.
// Run from engine: go test ./internal/registry -run TestRuntimeRegistry -count=1
func TestRuntimeRegistryRequiresFixtures(t *testing.T) {
	for _, layout := range []string{"missing", "empty", "regular-file"} {
		t.Run(layout, func(t *testing.T) {
			previous := current.Load()
			t.Cleanup(func() { current.Store(previous) })
			current.Store(nil)

			dir := runtimeRegistryFixture(t)
			fixtures := filepath.Join(dir, "fixtures")
			switch layout {
			case "empty":
				if err := os.Mkdir(fixtures, 0o700); err != nil {
					t.Fatal(err)
				}
			case "regular-file":
				if err := os.WriteFile(fixtures, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := Load(dir); err == nil {
				t.Errorf("accepted %s fixtures: rule selectors are not a complete shipped registry", layout)
			}
			if Loaded() {
				t.Error("published a registry without its fixture vocabulary")
			}
		})
	}
}

// Positive control: the same rule with a real fixture bundle is usable, and
// vocabulary contributed only by that bundle must survive loading.
func TestRuntimeRegistryLoadsCompleteBundle(t *testing.T) {
	previous := current.Load()
	t.Cleanup(func() { current.Store(previous) })
	current.Store(nil)
	dir := runtimeRegistryFixture(t)
	fixtures := filepath.Join(dir, "fixtures")
	if err := os.Mkdir(fixtures, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixtures, "events.ndjson"),
		[]byte("{\"source\":\"edr.kaspersky\",\"action\":\"file.read\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_SHIPPED_DIR", dir)
	if err := LoadEnv(); err != nil {
		t.Fatal(err)
	}
	if !Loaded() || !Source("host.sshd") || !Action("auth.ssh") ||
		!Source("edr.kaspersky") || !Action("file.read") {
		t.Fatal("complete registry lost rule or fixture vocabulary")
	}
}

func runtimeRegistryFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	const rule = `id: qa-shipped-ssh
title: QA shipped SSH rule
level: high
detection:
  selection:
    source: host.sshd
    action: auth.ssh
  condition: selection
`
	if err := os.WriteFile(filepath.Join(dir, "rules", "ssh.yml"), []byte(rule), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}
