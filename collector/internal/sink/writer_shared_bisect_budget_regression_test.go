package sink

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Whole-batch attempts and their backoff already share a loop. The bisection
// allowance must also survive those retries: a size failure followed by
// transport failures on singletons must not replenish 128 extra INSERTs.
func TestPR43ThirdRoundBisectBudgetIsSharedAcrossRetries(t *testing.T) {
	const size = 64
	st := &Stats{}
	q := NewQueue(2*size, st)
	rows := make([]any, size)
	for i := range rows {
		rows[i] = ev(fmt.Sprintf("pending-%d", i))
	}
	if err := q.Push(rows); err != nil {
		t.Fatal(err)
	}
	q.Close()
	b, ok := q.Pop()
	if !ok {
		t.Fatal("fixture batch missing")
	}
	calls, rejected := 0, 0
	transportErr := errors.New("fixture: singleton INSERT timed out")
	ins := pr43ReviewRetryInserter{
		events: func(part []any) error {
			calls++
			if calls > 8*size {
				t.Fatal("unexpected unbounded retry loop")
			}
			if len(part) > 1 {
				return &Error{Table: "events", Status: 500, Code: 241}
			}
			return transportErr
		},
		rejects: func(part []Reject) error {
			rejected += len(part)
			return nil
		},
	}
	w := NewWriter(ins, q, st)
	w.Attempts = 3
	w.Backoff, w.MaxBackoff = time.Millisecond, 8*time.Millisecond
	var sleeps []time.Duration
	w.Sleep = func(_ context.Context, d time.Duration) bool {
		sleeps = append(sleeps, d)
		return true
	}
	w.WriteBatch(context.Background(), b)

	// Allow every normal outer attempt in addition to the 128 bisection INSERTs.
	if limit := w.Attempts + bisectBudget; calls > limit {
		t.Errorf("bisection budget reset within one WriteBatch: calls=%d limit=%d", calls, limit)
	}
	if rejected != 0 || st.Inserted.Load() != 0 || q.Rows() != size {
		t.Errorf("transport-ambiguous rows must stay pending: rejects=%d inserted=%d pending=%d", rejected, st.Inserted.Load(), q.Rows())
	}
	if st.Retries.Load() != 2 || st.Requeued.Load() != 1 {
		t.Errorf("outer retry accounting: retries=%d requeued=%d", st.Retries.Load(), st.Requeued.Load())
	}
	wantSleeps := []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	if len(sleeps) != len(wantSleeps) {
		t.Fatalf("backoff/requeue sleeps=%v want=%v", sleeps, wantSleeps)
	}
	for i, want := range wantSleeps {
		if sleeps[i] != want {
			t.Errorf("backoff[%d]=%v want=%v", i, sleeps[i], want)
		}
	}
}
