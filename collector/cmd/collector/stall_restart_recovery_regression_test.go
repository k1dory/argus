package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// main creates a fresh stallWatch on each collector start. The incident opened
// by the previous process remains in the engine, however, and this rule has no
// auto_close. Restarting the collector and draining its spool must eventually
// produce a recovery even if no batch stalls for another SINK_STALL_AFTER.
func TestPR53StallRecoverySurvivesCollectorRestart(t *testing.T) {
	for _, phase := range []string{"open_episode", "undelivered_recovery"} {
		t.Run(phase, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			stuck := defaultStallAfter
			failRecovery := false
			var stored []model.Event
			newWatch := func() *stallWatch {
				// The same construction as main: the spool's observation is the
				// only state supplied to a new watcher, with no episode restored.
				return &stallWatch{
					after:   defaultStallAfter,
					stuck:   func(time.Time) time.Duration { return stuck },
					pending: func() int { return 0 },
					passes:  func() uint64 { return 0 },
					insert: func(_ context.Context, rows []any) error {
						for _, row := range rows {
							if failRecovery && row.(model.Event).Action == "collector.sink_recovered" {
								return errors.New("fixture: recovery INSERT unavailable")
							}
						}
						for _, row := range rows {
							stored = append(stored, row.(model.Event))
						}
						return nil
					},
				}
			}

			beforeRestart := newWatch()
			beforeRestart.tick(context.Background(), now)
			if len(stored) != 1 || stored[0].Action != "collector.sink_stalled" {
				t.Fatalf("fixture must deliver the event opening the incident: %+v", stored)
			}
			if phase == "undelivered_recovery" {
				stuck, failRecovery = 0, true
				beforeRestart.tick(context.Background(), now.Add(30*time.Second))
				if len(stored) != 1 || len(beforeRestart.outbox) != 1 {
					t.Fatal("fixture must leave recovery undelivered before restart")
				}
			}

			// After restart the spool has drained before the first watcher tick.
			// The ClickHouse destination (and the engine incident) survives it.
			stuck, failRecovery = 0, false
			afterRestart := newWatch()
			for i := 1; i <= 3; i++ {
				afterRestart.tick(context.Background(), now.Add(time.Duration(i+2)*30*time.Second))
			}
			actions := make([]string, len(stored))
			for i, event := range stored {
				actions[i] = event.Action
			}
			const want = "collector.sink_stalled,collector.sink_recovered"
			if got := strings.Join(actions, ","); got != want {
				t.Fatalf("healthy restart leaves a41c-ops-066 open indefinitely: delivered=%q want=%q", got, want)
			}
		})
	}
}
