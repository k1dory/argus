package main

import (
	"context"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/sink"
)

type pr55StallInserter struct {
	events func([]any) error
}

func (s pr55StallInserter) InsertEvents(_ context.Context, rows []any) error {
	return s.events(rows)
}

func (s pr55StallInserter) InsertRejects(context.Context, []sink.Reject) error {
	return &sink.Error{Table: "ingest_rejects", Status: 500, Code: 159}
}

// Restart restores the unacknowledged spool file but not its stall mark. Until
// the first writer pass finishes, StuckFor is zero even though no data has made
// progress. A slow INSERT and its retries can keep that pass in flight beyond
// the watcher's first 30-second tick. Its small internal notification may still
// succeed, falsely closing a41c-ops-066 for the ongoing outage.
func TestPR55RestartDoesNotRecoverUnacknowledgedSpool(t *testing.T) {
	for _, phase := range []string{"queued", "in_flight"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			t0 := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
			dir := t.TempDir()
			stats := &sink.Stats{}
			q, err := sink.NewDurableQueue(dir, 1<<20, stats)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(q.Close)
			if err := q.Push([]any{model.Event{
				TS: model.FormatTS(t0), Source: "fixture", Action: "fixture.pending",
				Node: "fixture-node", Attrs: map[string]string{},
			}}); err != nil {
				t.Fatal(err)
			}

			var stored []model.Event
			ins := pr55StallInserter{events: func(rows []any) error {
				for _, row := range rows {
					if row.(model.Event).Source != "argus.collector" {
						return &sink.Error{Table: "events", Status: 500, Code: 159}
					}
				}
				for _, row := range rows {
					stored = append(stored, row.(model.Event))
				}
				return nil
			}}
			newWatch := func(queue *sink.Queue, st *sink.Stats) *stallWatch {
				return &stallWatch{
					after: defaultStallAfter, stuck: queue.StuckFor, pending: queue.Rows,
					passes: st.StalledPasses.Load, insert: ins.InsertEvents,
				}
			}
			pop := func(queue *sink.Queue) sink.Batch {
				t.Helper()
				if queue.Rows() != 1 {
					t.Fatalf("expected one unacknowledged row, got %d", queue.Rows())
				}
				batch, ok := queue.Pop()
				if !ok || len(batch.Rows) != 1 {
					t.Fatalf("pop: ok=%t rows=%d", ok, len(batch.Rows))
				}
				return batch
			}
			writer := sink.NewWriter(ins, q, stats)
			writer.Attempts = 1
			writer.Sleep = func(context.Context, time.Duration) bool { return true }
			writer.Now = func() time.Time { return t0 }
			writer.WriteBatch(ctx, pop(q))
			if stats.Inserted.Load() != 0 || q.StuckFor(t0.Add(defaultStallAfter)) != defaultStallAfter {
				t.Fatal("fixture must establish a stalled durable batch without progress")
			}
			newWatch(q, stats).tick(ctx, t0.Add(defaultStallAfter))
			if len(stored) != 1 || stored[0].Action != "collector.sink_stalled" {
				t.Fatalf("fixture must deliver the incident-opening stall: %+v", stored)
			}
			q.Close()

			// The same startup path as main: fresh Stats, durable queue and watch.
			restartedStats := &sink.Stats{}
			restarted, err := sink.NewDurableQueue(dir, 1<<20, restartedStats)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(restarted.Close)
			if restarted.Rows() != 1 {
				t.Fatal("restart must replay the still-unacknowledged spool file")
			}
			var inFlight sink.Batch
			if phase == "in_flight" {
				// Pop removes the row from Rows before its INSERT has succeeded:
				// merely adding pending() == 0 to the startup guard is insufficient.
				inFlight = pop(restarted)
				if restarted.Rows() != 0 {
					t.Fatal("fixture must model an INSERT already owned by a writer")
				}
			}
			firstTick := t0.Add(defaultStallAfter + time.Minute + 30*time.Second)
			watch := newWatch(restarted, restartedStats)
			watch.tick(ctx, firstTick)

			// Complete the first post-restart pass with the same failure. This
			// establishes that the batch never recovered around the first tick.
			if phase == "queued" {
				inFlight = pop(restarted)
			}
			writer = sink.NewWriter(ins, restarted, restartedStats)
			writer.Attempts = 1
			writer.Sleep = func(context.Context, time.Duration) bool { return true }
			writer.Now = func() time.Time { return firstTick.Add(time.Second) }
			writer.WriteBatch(ctx, inFlight)
			if restarted.Rows() != 1 || restartedStats.Inserted.Load() != 0 || restartedStats.StalledPasses.Load() == 0 {
				t.Fatal("fixture must retain the same failed batch after restart")
			}
			watch.tick(ctx, firstTick.Add(30*time.Second))
			for _, event := range stored[1:] {
				if event.Action == "collector.sink_recovered" {
					t.Errorf("restart falsely recovered an unacknowledged batch: ts=%s startup=%s pending_at_event=%s inserted=%d",
						event.TS, event.Attrs["startup"], event.Attrs["pending_rows"], restartedStats.Inserted.Load())
				}
			}
		})
	}
}
