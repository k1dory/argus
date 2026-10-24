package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// Сторож диска пишет событие телеметрии, а не инцидент: инцидент заводит
// правило rules/ops/argus-disk-low.yml по тому же событию.
func TestCheckDisksWritesTelemetryEvent(t *testing.T) {
	f := newFakeCH(t)
	f.selects["system.disks"] = `{"name":"default","path":"/var/lib/clickhouse/","free_space":17179869184,"total_space":214748364800}` + "\n" +
		`{"name":"cold","path":"/mnt/cold/","free_space":500000000000,"total_space":1000000000000}` + "\n"
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	now := time.Date(2026, 10, 20, 10, 45, 0, 0, time.UTC)
	e.checkDisks(context.Background(), now)

	rows := f.waitRows(t, "events", 1)
	var ev model.Event
	if err := json.Unmarshal([]byte(rows[0]), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Source != "argus.system" || ev.SourceClass != "telemetry" || ev.Action != "disk.usage" || ev.Unit != "percent" || ev.Value != 92 {
		t.Fatalf("событие %+v", ev)
	}
	if ev.Node != "127.0.0.1" || ev.Object != "/var/lib/clickhouse/" || ev.Attrs["disk"] != "default" || ev.TS != "2026-10-20 10:45:00.000" {
		t.Fatalf("узел/объект %+v", ev)
	}
	if e.m.diskFreePermille.Load() != 80 {
		t.Fatalf("метрика свободного места %d‰, ожидалось 80", e.m.diskFreePermille.Load())
	}
	if len(f.rows("incidents")) != 0 {
		t.Fatal("сторож диска сам инцидентов не заводит")
	}

	// Событие проходит правило из репозитория: ≥ 90 % → critical по узлу ClickHouse, < 85 % закрывает.
	rs, err := rules.Load("../../../rules/ops")
	if err != nil {
		t.Fatal(err)
	}
	var disk *rules.Rule
	for _, r := range rs {
		if r.ID == "a41c-ops-062" {
			disk = r
		}
	}
	if disk == nil {
		t.Fatal("правило argus-disk-low не найдено")
	}
	dets, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{disk}, Events: []*model.Event{&ev}, Now: now})
	if len(dets) != 1 || dets[0].Key != "127.0.0.1" || len(closers) != 0 {
		t.Fatalf("dets=%d closers=%d", len(dets), len(closers))
	}
	ok := diskEvent(now.Add(time.Minute), "127.0.0.1", store.Disk{Name: "default", Path: "/", Free: 50, Total: 100}, 0.5)
	if _, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{disk}, Events: []*model.Event{ok}, Now: now}); len(closers) != 1 || closers[0].Key != "127.0.0.1" {
		t.Fatalf("замер 50 %% должен закрывать инцидент: %+v", closers)
	}
	if strings.Contains(rows[0], "received_at") {
		t.Fatal("received_at ставит ClickHouse по умолчанию")
	}
}

// Ошибка чтения system.disks не роняет цикл и ничего не пишет.
func TestCheckDisksSkipsWithoutData(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), respond.Config{}, "s", "s")
	e.checkDisks(context.Background(), time.Now())
	time.Sleep(20 * time.Millisecond)
	if len(f.rows("events")) != 0 {
		t.Fatalf("без данных о дисках событий быть не должно: %v", f.rows("events"))
	}
}
