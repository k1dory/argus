package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

func simpleRule(id, action string) string {
	return "title: " + id + "\nid: " + id + "\nlevel: low\ndetection:\n  selection: {action: " + action + "}\n  condition: selection\n"
}

func ruleByID(t *testing.T, s ruleSet, id string) (file, action string) {
	t.Helper()
	rs, _, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.ID == id {
			return r.File, r.Detection.Selection["action"].(string)
		}
	}
	return "", ""
}

// Поставляемое правило главнее: пользовательское с тем же id отвергается, а не
// подменяет штатный детект; дубль внутри пользовательских — тоже отказ; прочие
// пользовательские загружаются с префиксом user/.
func TestRuleSetShippedWinsAndUserDuplicatesRejected(t *testing.T) {
	shipped := rulesDirWith(t, map[string]string{"a.yml": simpleRule("r-ship", "ship.action")})
	user := rulesDirWith(t, map[string]string{
		"evil.yml":  simpleRule("r-ship", "user.override"),
		"mine.yml":  simpleRule("r-user", "user.action"),
		"mine2.yml": simpleRule("r-user", "user.second"),
	})
	s := ruleSet{shipped: shipped, user: user}
	rs, rejected, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("правил %d, ожидалось 2 (поставляемое и первое пользовательское)", len(rs))
	}
	if file, action := ruleByID(t, s, "r-ship"); file != "a.yml" || action != "ship.action" {
		t.Fatalf("штатный детект подменён: %s %s", file, action)
	}
	if file, action := ruleByID(t, s, "r-user"); file != "user/mine.yml" || action != "user.action" {
		t.Fatalf("пользовательское правило: %s %s", file, action)
	}
	got := map[string]string{}
	for _, r := range rejected {
		got[r.File] = r.Reason
	}
	if got["user/evil.yml"] != rejectShippedIDTaken || got["user/mine2.yml"] != rejectDuplicateID || len(got) != 2 {
		t.Fatalf("отказы: %+v", rejected)
	}
}

// Сбой разбора пользовательского каталога не останавливает движок: работают
// поставляемые, каталог отвергнут целиком. Без каталога или без RULES_USER_DIR —
// только поставляемые, без отказов. Ошибка поставляемых — ошибка набора.
func TestRuleSetUserParseErrorAndMissingDir(t *testing.T) {
	shipped := rulesDirWith(t, map[string]string{"a.yml": simpleRule("r-ship", "ship.action")})
	broken := rulesDirWith(t, map[string]string{"bad.yml": "id: [unterminated\n"})
	rs, rejected, err := ruleSet{shipped: shipped, user: broken}.load()
	if err != nil || len(rs) != 1 || len(rejected) != 1 || rejected[0].Reason != rejectParseError || rejected[0].File != userPrefix {
		t.Fatalf("битый пользовательский каталог: err=%v rules=%d rejected=%+v", err, len(rs), rejected)
	}
	for _, user := range []string{"", filepath.Join(t.TempDir(), "absent")} {
		rs, rejected, err := ruleSet{shipped: shipped, user: user}.load()
		if err != nil || len(rs) != 1 || len(rejected) != 0 {
			t.Fatalf("без пользовательских (%q): err=%v rules=%d rejected=%+v", user, err, len(rs), rejected)
		}
	}
	if _, _, err := (ruleSet{shipped: broken}).load(); err == nil {
		t.Fatal("битые поставляемые правила должны быть ошибкой набора")
	}
}

// Перечитывание видит изменения пользовательского каталога; отказы — в метрике
// и событиях argus.system / rules.rejected без текста ошибки.
func TestRuleSetReloadReportsRejected(t *testing.T) {
	f := newFakeCH(t)
	shipped := rulesDirWith(t, map[string]string{"a.yml": simpleRule("r-ship", "ship.action")})
	user := t.TempDir()
	e := testEngine(t, f, shipped, respond.Config{}, "s", "s")
	e.dirs = ruleSet{shipped: shipped, user: user}
	e.rulesSig = e.dirs.signature()
	if err := os.WriteFile(filepath.Join(user, "evil.yml"), []byte(simpleRule("r-ship", "user.override")), 0o644); err != nil {
		t.Fatal(err)
	}
	e.maybeReload(false)
	if e.m.rulesRejected.Load() != 1 || len(e.current()) != 1 || e.current()[0].Detection.Selection["action"] != "ship.action" {
		t.Fatalf("после перечитывания: rejected=%d rules=%d", e.m.rulesRejected.Load(), len(e.current()))
	}
	rows := f.waitRows(t, "events", 1)
	var ev model.Event
	if err := json.Unmarshal([]byte(rows[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Source != systemSource || ev.Action != "rules.rejected" || ev.Object != "user/evil.yml" ||
		ev.Attrs["transport"] != "internal" || ev.Attrs["rule_id"] != "r-ship" || ev.Attrs["reason"] != rejectShippedIDTaken {
		t.Fatalf("событие отказа: %+v", ev)
	}
	if strings.Contains(rows[0], "уже занят") {
		t.Fatal("текст ошибки попал в событие")
	}
	if err := os.Remove(filepath.Join(user, "evil.yml")); err != nil {
		t.Fatal(err)
	}
	e.maybeReload(false)
	if e.m.rulesRejected.Load() != 0 {
		t.Fatal("метрика не сбросилась после исправления каталога")
	}
}
