package sink

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Exhausting a work budget is not evidence that an untested row is invalid.
// A bounded pass may leave work pending, but every healthy event must remain in
// events or in the queue. For the durable path, inspect a freshly opened spool
// so an erroneous ack cannot be hidden by in-memory metadata.
func TestPR43ThirdRoundBudgetKeepsValidRows(t *testing.T) {
	const size = 500
	for _, durable := range []bool{false, true} {
		for _, failure := range []string{"size_only", "mixed_poison"} {
			t.Run(fmt.Sprintf("durable=%t/%s", durable, failure), func(t *testing.T) {
				st := &Stats{}
				q := NewQueue(2*size, st)
				var dir string
				if durable {
					dir = t.TempDir()
					var err error
					q, err = NewDurableQueue(dir, 1<<20, st)
					if err != nil {
						t.Fatal(err)
					}
				}
				rows := make([]any, size)
				poison := make(map[string]bool)
				for i := range rows {
					e := ev(fmt.Sprintf("event-%03d", i))
					rows[i] = e
					if failure == "mixed_poison" && i%7 == 0 {
						poison[e.Object] = true
					}
				}
				accepted := make(map[string]int)
				var rejects []Reject
				calls, rejectCalls := 0, 0
				ins := pr43ReviewRetryInserter{
					events: func(part []any) error {
						calls++
						if calls > 2*size {
							t.Fatal("unexpected retry loop in a bounded bisection fixture")
						}
						if failure == "size_only" && len(part) > 2 {
							return &Error{Table: "events", Status: 500, Code: 241}
						}
						for _, row := range part {
							if poison[row.(model.Event).Object] {
								return &Error{Table: "events", Status: 400, Code: 27}
							}
						}
						for _, row := range part {
							accepted[row.(model.Event).Object]++
						}
						return nil
					},
					rejects: func(part []Reject) error {
						rejectCalls++
						rejects = append(rejects, part...)
						return nil
					},
				}
				if err := q.Push(rows); err != nil {
					t.Fatal(err)
				}
				q.Close()
				b, ok := q.Pop()
				if !ok || b.loadErr != nil || len(b.Rows) != size {
					t.Fatalf("cannot load fixture: ok=%t rows=%d err=%v", ok, len(b.Rows), b.loadErr)
				}
				w := NewWriter(ins, q, st)
				w.Attempts = 1
				w.Sleep = func(context.Context, time.Duration) bool { return true }
				w.WriteBatch(context.Background(), b)
				if calls > 1+bisectBudget {
					t.Errorf("preserving valid rows must retain the work limit: calls=%d limit=%d", calls, 1+bisectBudget)
				}
				if rejectCalls > 1 {
					t.Errorf("rejects must remain batched: INSERT calls=%d", rejectCalls)
				}

				pendingQueue := q
				if durable {
					var err error
					pendingQueue, err = NewDurableQueue(dir, 1<<20, &Stats{})
					if err != nil {
						t.Fatal(err)
					}
				}
				pendingQueue.Close()
				pending := make(map[string]int)
				for rest, ok := pendingQueue.Pop(); ok; rest, ok = pendingQueue.Pop() {
					if rest.loadErr != nil {
						t.Fatal(rest.loadErr)
					}
					for _, row := range rest.Rows {
						pending[row.(model.Event).Object]++
					}
				}
				healthyRejected := 0
				for _, reject := range rejects {
					var e model.Event
					if err := json.Unmarshal([]byte(reject.Raw), &e); err != nil {
						t.Fatal(err)
					}
					if !poison[e.Object] {
						healthyRejected++
					}
				}
				if healthyRejected != 0 {
					t.Errorf("budget exhaustion classified %d healthy events as poison", healthyRejected)
				}
				missing := 0
				for _, row := range rows {
					id := row.(model.Event).Object
					if !poison[id] && accepted[id]+pending[id] == 0 {
						missing++
					}
				}
				if missing != 0 {
					t.Errorf("healthy events lost from events and replay: missing=%d inserted=%d pending=%d rejects=%d spool_bytes=%d",
						missing, len(accepted), len(pending), len(rejects), pendingQueue.SpoolBytes())
				}
			})
		}
	}
}
