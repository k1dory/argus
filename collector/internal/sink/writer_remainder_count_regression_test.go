package sink

import (
	"context"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Use Push/Pop rather than Writer.Write: only a real queued batch has a nonzero
// Count. Shrinking Rows without shrinking Count must not make a later Push
// evict unresolved events when the actual pending rows still fit the limit.
func TestPR43ThirdRoundRemainderCountDoesNotCauseEviction(t *testing.T) {
	st := &Stats{}
	q := NewQueue(4, st)
	if err := q.Push([]any{ev("poison"), ev("fine"), ev("timeout"), ev("fine2")}); err != nil {
		t.Fatal(err)
	}
	b, ok := q.Pop()
	if !ok || b.Count != 4 {
		t.Fatalf("fixture must use a queued four-row batch: ok=%t count=%d", ok, b.Count)
	}
	ins := &mockCH{}
	w := NewWriter(ins, q, st)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	w.WriteBatch(context.Background(), b)
	if ins.rows() != 1 || len(ins.rejects) != 1 || st.Requeued.Load() != 1 {
		t.Fatalf("fixture must resolve two rows and requeue the other two: inserted=%d rejects=%d requeued=%d",
			ins.rows(), len(ins.rejects), st.Requeued.Load())
	}
	if got := q.Rows(); got != 2 {
		t.Errorf("requeued remainder retained the original Count: pending=%d want=2", got)
	}
	if got, want := q.Bytes(), SizeOf([]any{ev("timeout"), ev("fine2")}); got != want {
		t.Errorf("remainder byte count=%d want=%d", got, want)
	}

	// Two unresolved rows plus two new rows fit the configured capacity of four.
	if err := q.Push([]any{ev("next1"), ev("next2")}); err != nil {
		t.Fatal(err)
	}
	if dropped := st.PendingDropped.Load(); dropped != 0 {
		t.Errorf("stale Count caused an unnecessary eviction: dropped=%d", dropped)
	}
	if got := q.Rows(); got != 4 {
		t.Errorf("pending rows after a Push that fits: got=%d want=4", got)
	}
	q.Close()
	pending := make(map[string]int)
	for rest, ok := q.Pop(); ok; rest, ok = q.Pop() {
		if rest.Count != len(rest.Rows) {
			t.Errorf("batch count=%d actual rows=%d", rest.Count, len(rest.Rows))
		}
		for _, row := range rest.Rows {
			pending[row.(model.Event).Object]++
		}
	}
	for _, id := range []string{"timeout", "fine2", "next1", "next2"} {
		if pending[id] != 1 {
			t.Errorf("unresolved event %q was lost: copies in queue=%d", id, pending[id])
		}
	}
}
