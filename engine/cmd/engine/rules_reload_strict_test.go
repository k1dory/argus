package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Правило с неизвестным движку полем при перечитывании отвергается целиком, и движок
// работает по прежнему набору: новый group_by не применяется без своей миграции.
func TestReloadKeepsRulesOnUnknownField(t *testing.T) {
	rule := "title: t\nid: t-strict\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n  group_by: attrs.peer\n"
	dir := rulesDirWith(t, map[string]string{"r.yml": rule})
	e := testEngine(t, newFakeCH(t), dir, respond.Config{}, "s", "s")
	if rs := e.current(); len(rs) != 1 || rs[0].GroupBy() != "attrs.peer" {
		t.Fatalf("фикстура: %+v", rs)
	}
	newer := rule[:len(rule)-len("  group_by: attrs.peer\n")] + "  group_by: attrs.peer, attrs.source\n  group_by_next: attrs.peer\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(newer), 0o600); err != nil {
		t.Fatal(err)
	}
	e.maybeReload(true)
	if rs := e.current(); len(rs) != 1 || rs[0].GroupBy() != "attrs.peer" {
		t.Fatalf("набор с неизвестным полем применён: group_by=%q", rs[0].GroupBy())
	}
}
