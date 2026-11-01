package sink

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type pr43ReviewRetryInserter struct {
	events  func([]any) error
	rejects func([]Reject) error
}

func (s pr43ReviewRetryInserter) InsertEvents(_ context.Context, rows []any) error {
	return s.events(rows)
}

func (s pr43ReviewRetryInserter) InsertRejects(_ context.Context, rows []Reject) error {
	return s.rejects(rows)
}

// Cancellation can arrive while the initial INSERT is in flight. Resolving a
// two-row batch requires at most three data-error attempts, even if shutdown
// permits a final flush. Returning the unchanged remainder to WriteBatch must
// not start the same operation recursively forever. Fail inside the fake after
// that finite tree, rather than actually overflowing the goroutine stack.
func TestPR43ReviewCanceledBisectionTerminates(t *testing.T) {
	for _, code := range []int{27, 241} {
		t.Run(fmt.Sprintf("code=%d", code), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			ins := pr43ReviewRetryInserter{
				events: func([]any) error {
					calls++
					if calls > 3 {
						t.Fatalf("canceled two-row bisection restarted instead of returning: INSERT calls=%d", calls)
					}
					cancel()
					return &Error{Table: "events", Status: 500, Code: code}
				},
				rejects: func([]Reject) error { return nil },
			}
			st := &Stats{}
			w := NewWriter(ins, NewQueue(10, st), st)
			w.Attempts = 1
			w.Sleep = func(context.Context, time.Duration) bool { return false }
			w.Write(ctx, []any{ev("first"), ev("second")})
			if calls == 0 {
				t.Fatal("fixture did not attempt the initial INSERT")
			}
		})
	}
}

// A size error on the whole batch and transport failures on both halves must
// eventually back off and requeue. Recombining the halves into the original
// oversized batch must not reset Attempts on an unbounded recursive cycle.
// The call guard includes a full split tree plus one retry per row, so a normal
// bounded implementation has ample room without the test needing a timeout.
func TestPR43ReviewBisectionTransportRemainderHonorsRetryBudget(t *testing.T) {
	const size = 4
	st := &Stats{}
	q := NewQueue(100, st)
	calls, rejected, sleeps := 0, 0, 0
	ins := pr43ReviewRetryInserter{
		events: func(rows []any) error {
			calls++
			if calls > (2*size-1)+size {
				t.Fatalf("bisection keeps rebuilding the oversized batch: calls=%d sleeps=%d requeued=%d", calls, sleeps, st.Requeued.Load())
			}
			if len(rows) > 2 {
				return &Error{Table: "events", Status: 500, Code: 241}
			}
			return errors.New("fixture: transport unavailable for smaller requests")
		},
		rejects: func(rows []Reject) error {
			rejected += len(rows)
			return nil
		},
	}
	w := NewWriter(ins, q, st)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool {
		sleeps++
		return true
	}
	w.Write(context.Background(), []any{ev("a"), ev("b"), ev("c"), ev("d")})
	if q.Rows() != size || st.Requeued.Load() == 0 || sleeps == 0 {
		t.Errorf("unresolved rows must reach backoff/requeue: pending=%d requeued=%d sleeps=%d", q.Rows(), st.Requeued.Load(), sleeps)
	}
	if rejected != 0 || st.Inserted.Load() != 0 {
		t.Errorf("transport failure must preserve all rows: rejected=%d inserted=%d", rejected, st.Inserted.Load())
	}
}
