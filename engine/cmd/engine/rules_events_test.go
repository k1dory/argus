package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Отказ правила виден: событие rules.rejected (object — файл, attrs.rule_id,
// attrs.reason — код без содержимого правила, attrs.transport: internal) уходит в
// argus.events, метрика растёт; файл снова загрузился, а инцидент a41c-ops-068 по
// нему открыт — rules.recovered.
func TestRulesRejectedEventsAndRecovery(t *testing.T) {
	good := "title: t\nid: t-ev\nlevel: low\ndetection:\n  selection: {action: x}\n  condition: selection\n"
	ops, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "ops", "rules-rejected.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := rulesDirWith(t, map[string]string{"r.yml": good, "ops.yml": string(ops)})
	f := newFakeCH(t)
	e := testEngine(t, f, dir, respond.Config{}, "s", "s")
	ctx := context.Background()

	bad := good + "  group_by_next: attrs.peer\n"
	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if rejected := e.maybeReload(true); len(rejected) != 1 || e.m.rulesRejected.Load() != 1 {
		t.Fatalf("отказ: %+v, метрика %d", rejected, e.m.rulesRejected.Load())
	}
	e.flushRulesEvents(ctx)
	evs := eventsOf(t, f)
	if len(evs) != 1 {
		t.Fatalf("события отказа: %+v", evs)
	}
	ev := evs[0]
	if ev.Source != systemSource || ev.Action != "rules.rejected" || ev.Object != "shipped/r.yml" || ev.Attrs["transport"] != "internal" ||
		ev.Attrs["rule_id"] != "t-ev" || ev.Attrs["reason"] != "schema_unknown_field" {
		t.Fatalf("поля события отказа: %+v", ev)
	}
	if _, leaked := ev.Attrs["error"]; leaked {
		t.Fatal("текст ошибки ушёл в событие")
	}
	if created, _, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{&ev}), time.Now()); len(created) != 1 || created[0].GroupKey != "shipped/r.yml" {
		t.Fatalf("инцидент отказа: %+v", created)
	}

	if err := os.WriteFile(filepath.Join(dir, "r.yml"), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	if rejected := e.maybeReload(true); len(rejected) != 0 || e.m.rulesRejected.Load() != 0 {
		t.Fatalf("исправленное правило не загрузилось: %+v", rejected)
	}
	e.flushRulesEvents(ctx)
	evs = eventsOf(t, f)
	if len(evs) != 2 || evs[1].Action != "rules.recovered" || evs[1].Object != "shipped/r.yml" || evs[1].Attrs["transport"] != "internal" {
		t.Fatalf("восстановление: %+v", evs)
	}
	// Сбой записи — событие не теряется, повтор на следующем цикле.
	e.reloadMu.Lock()
	e.rulesPending = append(e.rulesPending, rulesRejectedEvent(time.Now(), "n", "x.yml", "", "parse_error"))
	e.reloadMu.Unlock()
	setFail(f, "events", true)
	e.flushRulesEvents(ctx)
	setFail(f, "events", false)
	e.flushRulesEvents(ctx)
	if evs = eventsOf(t, f); len(evs) != 3 || evs[2].Object != "x.yml" {
		t.Fatalf("повтор после сбоя записи: %d событий", len(evs))
	}
}

func eventsOf(t *testing.T, f *fakeCH) []model.Event {
	t.Helper()
	var out []model.Event
	for _, line := range f.rows("events") {
		var ev model.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		out = append(out, ev)
	}
	return out
}
