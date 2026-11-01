package main

import (
	"context"
	"log/slog"
	"math"
	"os"
	"strconv"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Стоп-сигнал записи. Батч, который проход за проходом возвращается в очередь без
// прогресса (sink.Queue.StuckFor), — признак полумёртвого ClickHouse: данные целы,
// но не идут. Дольше SINK_STALL_AFTER (10m; 0 — выключено) — ERROR в журнал и
// событие argus.collector / collector.sink_stalled мимо очереди (она и стоит); на
// него срабатывает правило эксплуатации ops/collector-sink-stalled. Когда застрявших
// батчей не остаётся — collector.sink_recovered, оно закрывает инцидент.

const defaultStallAfter = 10 * time.Minute

type stallWatch struct {
	after    time.Duration
	stuck    func(now time.Time) time.Duration
	pending  func() int
	passes   func() uint64
	insert   func(ctx context.Context, rows []any) error
	reported bool // событие о застревании записано, ждём восстановления
}

func stallAfter() time.Duration {
	v := os.Getenv("SINK_STALL_AFTER")
	if v == "" {
		return defaultStallAfter
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		slog.Warn("SINK_STALL_AFTER: ожидалась длительность (10m), взято по умолчанию", "value", v)
		return defaultStallAfter
	}
	return d
}

func (w *stallWatch) tick(ctx context.Context, now time.Time) {
	if w.after <= 0 {
		return
	}
	d := w.stuck(now)
	switch {
	case d >= w.after && !w.reported:
		slog.Error("запись в ClickHouse стоит: батч не продвигается", "stuck", d.Round(time.Second), "pending_rows", w.pending(), "stalled_passes", w.passes())
		if err := w.insert(ctx, []any{w.event(now, "collector.sink_stalled", "failure", d)}); err != nil {
			slog.Warn("событие collector.sink_stalled не записано, повтор на следующем такте", "err", err)
			return
		}
		w.reported = true
	case d == 0 && w.reported:
		if err := w.insert(ctx, []any{w.event(now, "collector.sink_recovered", "success", 0)}); err != nil {
			slog.Warn("событие collector.sink_recovered не записано, повтор на следующем такте", "err", err)
			return
		}
		slog.Info("запись в ClickHouse снова идёт")
		w.reported = false
	}
}

func (w *stallWatch) event(now time.Time, action, outcome string, stuck time.Duration) model.Event {
	e := model.Event{
		TS: model.FormatTS(now), Source: "argus.collector", SourceClass: "telemetry", Vendor: "ARGUS", Product: "collector",
		Action: action, Outcome: outcome, ActorName: "argus-collector", ActorKind: "system", Node: "argus-collector",
		Value: math.Round(stuck.Seconds()), Unit: "seconds",
		Attrs: map[string]string{
			"pending_rows":   strconv.Itoa(w.pending()),
			"stalled_passes": strconv.FormatUint(w.passes(), 10),
			"transport":      "internal",
		},
	}
	if outcome == "failure" {
		e.Severity = 7
	}
	e.Sanitize()
	return e
}

func (w *stallWatch) run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			w.tick(ctx, now)
		case <-ctx.Done():
			return
		}
	}
}
