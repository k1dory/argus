package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/sink"
)

// A transport outage can leave both edges of an episode in the outbox. When
// ClickHouse starts accepting small INSERTs again, a divisible error on the
// combined batch must not prevent delivery forever. Retrying smaller prefixes
// on subsequent ticks preserves both FIFO and the one-INSERT-per-tick budget.
func TestPR53StallOutboxMakesProgressAfterDivisibleError(t *testing.T) {
	for _, maxRows := range []int{1, stallOutboxMax} {
		t.Run(fmt.Sprintf("accepted_batch_rows=%d", maxRows), func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			stuck := defaultStallAfter
			unavailable := true
			attempts := 0
			var stored []model.Event
			w := &stallWatch{
				after:   defaultStallAfter,
				stuck:   func(time.Time) time.Duration { return stuck },
				pending: func() int { return 1 },
				passes:  func() uint64 { return 1 },
				insert: func(_ context.Context, rows []any) error {
					attempts++
					if unavailable {
						return &sink.Error{Table: "events", Status: 500, Code: 159}
					}
					if len(rows) > maxRows {
						return &sink.Error{Table: "events", Status: 500, Code: 241}
					}
					for _, row := range rows {
						stored = append(stored, row.(model.Event))
					}
					return nil
				},
			}
			tick := func(at time.Time) {
				t.Helper()
				before := attempts
				w.tick(context.Background(), at)
				if n := attempts - before; n > 1 {
					t.Fatalf("one tick made %d INSERT attempts; retry on the next tick", n)
				}
			}

			tick(now)
			if attempts != 1 || len(stored) != 0 || len(w.outbox) != 1 {
				t.Fatalf("fixture must retain an undelivered stall: attempts=%d stored=%d pending=%d", attempts, len(stored), len(w.outbox))
			}

			// The durable writer has drained its batch (it can bisect code 241),
			// so recovery joins the failed notification before the next INSERT.
			unavailable, stuck = false, 0
			for i := 1; i <= 6; i++ {
				tick(now.Add(time.Duration(i) * 30 * time.Second))
			}
			actions := make([]string, len(stored))
			for i, event := range stored {
				actions[i] = event.Action
			}
			const want = "collector.sink_stalled,collector.sink_recovered"
			if got := strings.Join(actions, ","); got != want {
				t.Fatalf("outbox cannot recover from a divisible INSERT error: delivered=%q want=%q pending=%d attempts=%d", got, want, len(w.outbox), attempts)
			}
			if len(w.outbox) != 0 {
				t.Fatalf("successfully delivered events remain pending: %d", len(w.outbox))
			}
			if stored[0].TS != model.FormatTS(now) || stored[1].TS != model.FormatTS(now.Add(30*time.Second)) {
				t.Fatalf("retry changed occurrence times: stalled=%s recovered=%s", stored[0].TS, stored[1].TS)
			}
		})
	}
}
