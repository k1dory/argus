package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Поставляемое правило главнее и при перечитывании: пользовательское, активное с
// этим id раньше, отвергается (shipped_id_taken) одной записью, хотя его прежняя
// версия тоже держит этот id.
func TestRuleSetReloadShippedBeatsPreviouslyActiveUserRule(t *testing.T) {
	f := newFakeCH(t)
	shipped := rulesDirWith(t, map[string]string{"a.yml": simpleRule("r-ship", "ship.action")})
	user := rulesDirWith(t, map[string]string{"mine.yml": simpleRule("r-new", "user.action")})
	e := testEngine(t, f, shipped, respond.Config{}, "s", "s")
	e.dirs = ruleSet{shipped: shipped, user: user}
	if rejected := e.maybeReload(true); len(rejected) != 0 || e.ruleFor("r-new") == nil || !e.ruleFor("r-new").User {
		t.Fatalf("пользовательское правило не загрузилось: %+v", rejected)
	}
	if err := os.WriteFile(filepath.Join(shipped, "b.yml"), []byte(simpleRule("r-new", "ship.new")), 0o600); err != nil {
		t.Fatal(err)
	}
	rejected := e.maybeReload(true)
	if len(rejected) != 1 || rejected[0].Reason != rejectShippedIDTaken || rejectKey(rejected[0]) != "user/mine.yml" {
		t.Fatalf("отказы: %+v", rejected)
	}
	if r := e.ruleFor("r-new"); r == nil || r.User || r.Detection.Selection["action"] != "ship.new" {
		t.Fatalf("поставляемое правило не заняло id: %+v", r)
	}
	if len(e.rulesPending) != 1 || e.rulesPending[0].Object != "user/mine.yml" || e.m.rulesRejected.Load() != 1 {
		t.Fatalf("событие отказа: %+v, метрика %d", e.rulesPending, e.m.rulesRejected.Load())
	}
}

// Поставляемый user/a.yml и пользовательский a.yml — разные файлы: прежняя версия
// отвергнутого поставляемого сохраняется только для него, object — shipped/user/a.yml.
func TestRuleSetReloadKeysByOriginNotPath(t *testing.T) {
	f := newFakeCH(t)
	shipped := t.TempDir()
	if err := os.Mkdir(filepath.Join(shipped, "user"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(shipped, "user", "a.yml")
	if err := os.WriteFile(path, []byte(simpleRule("r-ship", "ship.action")), 0o600); err != nil {
		t.Fatal(err)
	}
	user := rulesDirWith(t, map[string]string{"a.yml": simpleRule("r-user", "user.action")})
	e := testEngine(t, f, shipped, respond.Config{}, "s", "s")
	e.dirs = ruleSet{shipped: shipped, user: user}
	if rejected := e.maybeReload(true); len(rejected) != 0 || len(e.current()) != 2 {
		t.Fatalf("набор: %d правил, отказы %+v", len(e.current()), rejected)
	}
	if err := os.WriteFile(path, []byte("id: [unterminated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rejected := e.maybeReload(true)
	if len(rejected) != 1 || rejectKey(rejected[0]) != "shipped/user/a.yml" {
		t.Fatalf("отказы: %+v", rejected)
	}
	if r := e.ruleFor("r-ship"); r == nil || r.User || r.Detection.Selection["action"] != "ship.action" {
		t.Fatalf("прежняя версия поставляемого не сохранена: %+v", r)
	}
	if r := e.ruleFor("r-user"); r == nil || !r.User {
		t.Fatalf("пользовательское правило пропало: %+v", r)
	}
	if len(e.rulesPending) != 1 || e.rulesPending[0].Object != "shipped/user/a.yml" {
		t.Fatalf("событие отказа: %+v", e.rulesPending)
	}
}
