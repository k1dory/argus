package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Стоп-сигнал: одно событие collector.sink_stalled на эпизод (после порога), повтор,
// если запись события не удалась, и collector.sink_recovered, когда застрявших нет.
func TestStallWatchEmitsOncePerEpisode(t *testing.T) {
	stuck := time.Duration(0)
	fail := false
	var got []model.Event
	w := &stallWatch{
		after:   10 * time.Minute,
		stuck:   func(time.Time) time.Duration { return stuck },
		pending: func() int { return 42 },
		passes:  func() uint64 { return 7 },
		insert: func(_ context.Context, rows []any) error {
			if fail {
				return errors.New("fixture: insert failed")
			}
			for _, r := range rows {
				got = append(got, r.(model.Event))
			}
			return nil
		},
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	tick := func() { w.tick(context.Background(), now) }

	stuck = 9 * time.Minute
	tick()
	if len(got) != 0 {
		t.Fatalf("до порога событий нет: %+v", got)
	}
	stuck, fail = 10*time.Minute, true
	tick()
	if len(got) != 0 || len(w.outbox) != 1 {
		t.Fatal("неудачная запись события не должна считаться отправленной")
	}
	fail = false
	tick()
	stuck = 30 * time.Minute
	tick()
	if len(got) != 1 {
		t.Fatalf("одно событие на эпизод, получено %d", len(got))
	}
	e := got[0]
	if e.Source != "argus.collector" || e.Action != "collector.sink_stalled" || e.Outcome != "failure" || e.Value != 600 || e.Unit != "seconds" ||
		e.Node != "argus-collector" || e.Attrs["pending_rows"] != "42" || e.Attrs["stalled_passes"] != "7" {
		t.Fatalf("событие застревания: %+v", e)
	}
	stuck = 0
	tick()
	tick()
	if len(got) != 2 || got[1].Action != "collector.sink_recovered" || got[1].Outcome != "success" {
		t.Fatalf("восстановление — одно событие: %+v", got)
	}
	// Новый эпизод — новое событие.
	stuck = 11 * time.Minute
	tick()
	if len(got) != 3 || got[2].Action != "collector.sink_stalled" {
		t.Fatalf("второй эпизод: %+v", got)
	}
}

func TestStallWatchDisabled(t *testing.T) {
	w := &stallWatch{after: 0, stuck: func(time.Time) time.Duration { return time.Hour },
		insert: func(context.Context, []any) error {
			t.Fatal("выключенный стоп-сигнал пишет события")
			return nil
		}}
	w.tick(context.Background(), time.Now())
	t.Setenv("SINK_STALL_AFTER", "0")
	if stallAfter() != 0 {
		t.Fatal("SINK_STALL_AFTER=0 выключает стоп-сигнал")
	}
	t.Setenv("SINK_STALL_AFTER", "мусор")
	if stallAfter() != defaultStallAfter {
		t.Fatal("неразборчивое значение — по умолчанию")
	}
}
