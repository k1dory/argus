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
// батчей не остаётся — collector.sink_recovered, оно закрывает инцидент. Оба
// события несут attrs.transport=internal: у входящих событий это поле всегда
// перезаписывает emit (udp/tcp/tls/http/file/pull), и правило по нему отличает
// настоящее событие коллектора от присланного через /ingest/events.

const defaultStallAfter = 10 * time.Minute

type stallWatch struct {
	after   time.Duration
	stuck   func(now time.Time) time.Duration
	pending func() int
	passes  func() uint64
	insert  func(ctx context.Context, rows []any) error
	// open — эпизод застревания начат (сообщение о нём поставлено в outbox).
	// outbox — события, ещё не записанные в ClickHouse: состояние и доставка
	// разделены, неудачная запись не теряет эпизод и не глушит следующий.
	open   bool
	outbox []model.Event
}

// stallOutboxMax — потолок неотправленных событий (при долгой недоступности
// ClickHouse старые пары «застряло / восстановилось» вытесняются).
const stallOutboxMax = 32

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

// tick — сменить состояние по возрасту застрявшего батча и доставить outbox одной
// вставкой (не больше одной попытки за такт).
func (w *stallWatch) tick(ctx context.Context, now time.Time) {
	if w.after <= 0 {
		return
	}
	d := w.stuck(now)
	switch {
	case d >= w.after && !w.open:
		slog.Error("запись в ClickHouse стоит: батч не продвигается", "stuck", d.Round(time.Second), "pending_rows", w.pending(), "stalled_passes", w.passes())
		w.open = true
		w.enqueue(w.event(now, "collector.sink_stalled", "failure", d))
	case d == 0 && w.open:
		slog.Info("запись в ClickHouse снова идёт")
		w.open = false
		w.enqueue(w.event(now, "collector.sink_recovered", "success", 0))
	}
	if len(w.outbox) == 0 {
		return
	}
	rows := make([]any, len(w.outbox))
	for i, e := range w.outbox {
		rows[i] = e
	}
	if err := w.insert(ctx, rows); err != nil {
		slog.Warn("события стоп-сигнала не записаны, повтор на следующем такте", "events", len(w.outbox), "err", err)
		return
	}
	w.outbox = w.outbox[:0]
}

func (w *stallWatch) enqueue(e model.Event) {
	if len(w.outbox) >= stallOutboxMax {
		w.outbox = append(w.outbox[:0], w.outbox[len(w.outbox)-stallOutboxMax+1:]...)
	}
	w.outbox = append(w.outbox, e)
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
