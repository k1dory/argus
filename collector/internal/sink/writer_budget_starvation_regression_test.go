package sink

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// A request containing expensive rows can exceed its memory limit, while a
// singleton containing one of those rows can time out. Neither result proves
// that an unvisited, inexpensive row is invalid. Keep both errors stable so a
// lack of progress cannot be attributed to a changing mock or a DB outage.
func TestPR43FourthRoundDurableBudgetDoesNotStarveUnverifiedTail(t *testing.T) {
	for _, size := range []int{16, 500} {
		t.Run(fmt.Sprintf("rows=%d", size), func(t *testing.T) {
			st := &Stats{}
			dir := t.TempDir()
			q, err := NewDurableQueue(dir, 1<<20, st)
			if err != nil {
				t.Fatal(err)
			}
			rows := make([]any, size)
			for i := range rows {
				prefix := "healthy"
				if i < size/2 {
					prefix = "blocked"
				}
				rows[i] = ev(fmt.Sprintf("%s-%03d", prefix, i))
			}
			if err := q.Push(rows); err != nil {
				t.Fatal(err)
			}
			q.Close() // A missing remainder must fail instead of blocking Pop.

			accepted := make(map[string]int)
			calls, sleeps, rejected := 0, 0, 0
			ins := pr43ReviewRetryInserter{
				events: func(part []any) error {
					calls++
					for _, row := range part {
						if strings.HasPrefix(row.(model.Event).Object, "blocked-") {
							if len(part) > 1 {
								return &Error{Table: "events", Status: 500, Code: 241}
							}
							return &Error{Table: "events", Status: 500, Code: 159}
						}
					}
					for _, row := range part {
						accepted[row.(model.Event).Object]++
					}
					return nil
				},
				rejects: func(part []Reject) error {
					rejected += len(part)
					return nil
				},
			}
			w := NewWriter(ins, q, st)
			w.Sleep = func(_ context.Context, delay time.Duration) bool {
				if delay <= 0 {
					t.Error("unresolved work must retain a positive backoff")
				}
				sleeps++
				return true
			}
			// This allows more than twice the INSERTs needed to visit a full
			// bisection tree. The 16-row control can reach the healthy suffix
			// in one pass; the 500-row case must continue beyond its first
			// budget rather than replaying that same prefix forever.
			passes := 4*size/bisectBudget + MaxRequeues + 1
			for pass := 0; pass < passes; pass++ {
				b, ok := q.Pop()
				if !ok || b.loadErr != nil || b.file == "" {
					t.Fatalf("cannot reload unresolved spool: ok=%t err=%v file=%q", ok, b.loadErr, b.file)
				}
				if b.Count != len(b.Rows) {
					t.Fatalf("remainder Count=%d, actual rows=%d", b.Count, len(b.Rows))
				}
				before := calls
				w.WriteBatch(context.Background(), b)
				if used := calls - before; used > bisectBudget+w.Attempts {
					t.Fatalf("progress must preserve the per-pass work bound: calls=%d", used)
				}
				if len(accepted) == size/2 {
					break
				}
			}
			if len(accepted) != size/2 {
				t.Errorf("healthy tail starved after %d bounded passes: inserted=%d want=%d pending=%d calls=%d",
					passes, len(accepted), size/2, q.Rows(), calls)
			}
			if rejected != 0 {
				t.Errorf("no singleton had a data error, but %d rows were rejected", rejected)
			}
			if sleeps == 0 {
				t.Error("unresolved work bypassed backoff")
			}

			// Failed/untested rows must also survive restart. This distinguishes
			// a progress fix from dropping or acknowledging the entire batch.
			recovered, err := NewDurableQueue(dir, 1<<20, &Stats{})
			if err != nil {
				t.Fatal(err)
			}
			recovered.Close()
			pending := make(map[string]int)
			for b, ok := recovered.Pop(); ok; b, ok = recovered.Pop() {
				if b.loadErr != nil {
					t.Fatal(b.loadErr)
				}
				for _, row := range b.Rows {
					pending[row.(model.Event).Object]++
				}
			}
			for _, row := range rows {
				id := row.(model.Event).Object
				if got := accepted[id] + pending[id]; got != 1 {
					t.Errorf("event %q must exist exactly once in events or replay: got %d", id, got)
				}
			}
		})
	}
}
