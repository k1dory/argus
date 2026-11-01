package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

func pr50ReviewStallActions(events []model.Event) string {
	actions := make([]string, len(events))
	for i, event := range events {
		actions[i] = event.Action
	}
	return strings.Join(actions, ",")
}

// ClickHouse can reject the notification for the same reason it rejects the
// queued batch. If writers drain the batch before the next watcher tick, the
// failed notification must still be retried, followed by its recovery.
func TestPR50ReviewStalledRetrySurvivesRecovery(t *testing.T) {
	now := time.Now().UTC()
	stuck, pending := 10*time.Minute, 1
	unavailable := true
	attempts := 0
	var stored []model.Event
	w := &stallWatch{
		after:   10 * time.Minute,
		stuck:   func(time.Time) time.Duration { return stuck },
		pending: func() int { return pending },
		passes:  func() uint64 { return 1 },
		insert: func(_ context.Context, rows []any) error {
			attempts++
			if attempts > 8 {
				t.Fatal("notification failure must not recursively retry in the same tick")
			}
			if unavailable {
				return errors.New("fixture: ClickHouse unavailable")
			}
			for _, row := range rows {
				stored = append(stored, row.(model.Event))
			}
			return nil
		},
	}
	w.tick(context.Background(), now)
	if attempts != 1 || len(stored) != 0 {
		t.Fatalf("fixture must reject one direct INSERT: attempts=%d stored=%v", attempts, stored)
	}

	// The outage ends between ticks, and the writers empty the spool first.
	unavailable, stuck, pending = false, 0, 0
	for tick := 1; tick <= 3; tick++ {
		w.tick(context.Background(), now.Add(time.Duration(tick)*30*time.Second))
	}
	const want = "collector.sink_stalled,collector.sink_recovered"
	if got := pr50ReviewStallActions(stored); got != want {
		t.Fatalf("failed stall notification was lost after recovery: stored=%q, want %q; INSERT attempts=%d", got, want, attempts)
	}
}

// A failed recovery INSERT must remain pending even when another stall starts.
// Otherwise reported stays true and suppresses the second episode forever.
func TestPR50ReviewFailedRecoveryDoesNotSuppressNextEpisode(t *testing.T) {
	now := time.Now().UTC()
	stuck := 10 * time.Minute
	failRecovery := false
	failedRecoveries := 0
	var stored []model.Event
	w := &stallWatch{
		after:   10 * time.Minute,
		stuck:   func(time.Time) time.Duration { return stuck },
		pending: func() int { return 1 },
		passes:  func() uint64 { return 2 },
		insert: func(_ context.Context, rows []any) error {
			for _, row := range rows {
				event := row.(model.Event)
				if failRecovery && event.Action == "collector.sink_recovered" {
					failedRecoveries++
					if failedRecoveries > 1 {
						t.Fatal("failed recovery must wait for another tick before retrying")
					}
					return errors.New("fixture: recovery INSERT rejected")
				}
				stored = append(stored, event)
			}
			return nil
		},
	}
	w.tick(context.Background(), now)
	stuck, failRecovery = 0, true
	w.tick(context.Background(), now.Add(30*time.Second))
	if failedRecoveries != 1 || pr50ReviewStallActions(stored) != "collector.sink_stalled" {
		t.Fatalf("fixture must retain the first stall and reject its recovery: failed=%d stored=%v", failedRecoveries, stored)
	}

	// A different batch has now been stalled beyond the threshold. The direct
	// notification INSERT works again, although the queued batch is still stuck.
	stuck, failRecovery = 10*time.Minute, false
	for tick := 0; tick < 3; tick++ {
		w.tick(context.Background(), now.Add(11*time.Minute+time.Duration(tick)*30*time.Second))
	}
	const want = "collector.sink_stalled,collector.sink_recovered,collector.sink_stalled"
	if got := pr50ReviewStallActions(stored); got != want {
		t.Fatalf("failed recovery swallowed the next episode: stored=%q, want %q", got, want)
	}
}
