package sink

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

func pr58RestoredQueue(t *testing.T, batches ...[]any) (*Queue, *Stats) {
	t.Helper()
	dir := t.TempDir()
	seed, err := NewDurableQueue(dir, 1<<20, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(seed.Close)
	for _, rows := range batches {
		if err := seed.Push(rows); err != nil {
			t.Fatal(err)
		}
	}
	seed.Close()
	stats := &Stats{}
	q, err := NewDurableQueue(dir, 1<<20, stats)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(q.Close)
	return q, stats
}

func pr58Writer(ins Inserter, q *Queue, stats *Stats) *Writer {
	w := NewWriter(ins, q, stats)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	w.Now = func() time.Time { return q.startedAt.Add(time.Minute) }
	return w
}

func pr58PartialInserter() Inserter {
	return pr43ReviewRetryInserter{
		events: func(rows []any) error {
			if len(rows) > 1 {
				return &Error{Table: "events", Status: 500, Code: 241}
			}
			switch rows[0].(model.Event).Object {
			case "timeout":
				return &Error{Table: "events", Status: 500, Code: 159}
			case "poison":
				return &Error{Table: "events", Status: 400, Code: 27}
			default:
				return nil
			}
		},
		rejects: func([]Reject) error { return nil },
	}
}

// A successful shrink accounts for the original batch exactly once. Retrying
// and then acknowledging its remainder must not consume another restored
// batch's recovery guard. A durable dead-letter must release that guard too.
func TestPR58RestoredShrinkThenAckCountsOnce(t *testing.T) {
	ctx := context.Background()
	q, stats := pr58RestoredQueue(t, []any{ev("accepted"), ev("timeout")}, []any{ev("poison")})
	if q.restoredPending != 2 {
		t.Fatalf("restored batches=%d, want 2", q.restoredPending)
	}
	for _, offset := range []time.Duration{-time.Second, 0, 30 * time.Second} {
		got := q.StuckFor(q.startedAt.Add(offset))
		if got <= 0 || got >= 10*time.Minute {
			t.Fatalf("startup must neither recover nor reach the default stall threshold: offset=%v stuck=%v", offset, got)
		}
	}
	partial, poison := pr50ReviewPop(t, q), pr50ReviewPop(t, q)
	if q.Rows() != 0 || q.StuckFor(q.startedAt.Add(30*time.Second)) != 30*time.Second {
		t.Fatal("in-flight restored batches must still prevent startup recovery")
	}
	w := pr58Writer(pr58PartialInserter(), q, stats)
	w.WriteBatch(ctx, partial)
	if q.restoredPending != 1 || q.Rows() != 1 {
		t.Fatalf("shrink must release just one restored batch: restored=%d rows=%d", q.restoredPending, q.Rows())
	}
	remainder := pr50ReviewPop(t, q)
	if remainder.restored {
		t.Fatal("the published remainder must not be accounted as restored again")
	}
	w.WriteBatch(ctx, remainder) // No progress on the remaining singleton.
	if q.restoredPending != 1 {
		t.Fatalf("unchanged retry altered restored accounting: %d", q.restoredPending)
	}
	acceptAll := pr43ReviewRetryInserter{
		events:  func([]any) error { return nil },
		rejects: func([]Reject) error { return nil },
	}
	pr58Writer(acceptAll, q, stats).WriteBatch(ctx, pr50ReviewPop(t, q))
	if q.restoredPending != 1 || q.StuckFor(q.startedAt.Add(2*time.Minute)) != 2*time.Minute {
		t.Fatal("ack of a shrunken remainder released the other in-flight restored batch")
	}
	w.WriteBatch(ctx, poison)
	if stats.DeadLetter.Load() != 1 || stats.RejectsFailed.Load() != 0 {
		t.Fatal("fixture must successfully dead-letter the final restored batch")
	}
	if q.restoredPending != 0 || q.StuckFor(q.startedAt.Add(2*time.Minute)) != 0 || q.SpoolBytes() != 0 {
		t.Fatalf("all batches resolved but startup guard remains: restored=%d stuck=%v spool=%d",
			q.restoredPending, q.StuckFor(q.startedAt.Add(2*time.Minute)), q.SpoolBytes())
	}
}

// Failure before publishing a smaller file must leave the restored guard in
// place, even if ClickHouse accepted part of the batch during bisection.
func TestPR58RestoredFailedShrinkKeepsStartupAge(t *testing.T) {
	q, stats := pr58RestoredQueue(t, []any{ev("accepted"), ev("timeout")})
	b := pr50ReviewPop(t, q)
	dir := q.spool.dir
	q.spool.dir = b.file // CreateTemp fails: a regular file is not a directory.
	t.Cleanup(func() { q.spool.dir = dir })
	w := pr58Writer(pr58PartialInserter(), q, stats)
	w.WriteBatch(context.Background(), b)
	q.spool.dir = dir
	if q.restoredPending != 1 || q.Rows() != 2 || stats.Inserted.Load() != 1 {
		t.Fatalf("failed shrink must retain the entire restored batch: restored=%d rows=%d inserted=%d",
			q.restoredPending, q.Rows(), stats.Inserted.Load())
	}
	if got := q.StuckFor(q.startedAt.Add(2 * time.Minute)); got != 2*time.Minute {
		t.Fatalf("failed shrink reset startup age: got=%v want=2m", got)
	}
	w.WriteBatch(context.Background(), pr50ReviewPop(t, q))
	if q.restoredPending != 0 || q.Rows() != 1 || q.StuckFor(q.startedAt.Add(2*time.Minute)) != 0 {
		t.Fatal("successful shrink after the filesystem recovers must release the startup guard")
	}
}

// Keep one restored batch in flight while several writers acknowledge others.
// Readers must never observe recovery early; the final ack must clear the guard.
// Run with -race to check the counter/metric synchronization as well.
func TestPR58RestoredConcurrentAcksKeepLastBatchPending(t *testing.T) {
	const writers = 4
	batches := make([][]any, writers+1)
	for i := range batches {
		batches[i] = []any{ev(fmt.Sprintf("accepted-%d", i))}
	}
	q, stats := pr58RestoredQueue(t, batches...)
	inFlight := make([]Batch, len(batches))
	for i := range inFlight {
		inFlight[i] = pr50ReviewPop(t, q)
	}
	ins := &mockCH{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, b := range inFlight[:writers] {
		wg.Add(1)
		go func(b Batch) {
			defer wg.Done()
			<-start
			pr58Writer(ins, q, stats).WriteBatch(context.Background(), b)
		}(b)
	}
	close(start)
	observedAt := q.startedAt.Add(30 * time.Second)
	for i := 0; i < 128; i++ {
		if got := q.StuckFor(observedAt); got != 30*time.Second {
			t.Errorf("last restored batch is still in flight: stuck=%v want=30s", got)
			break
		}
	}
	wg.Wait()
	if q.restoredPending != 1 || q.StuckFor(observedAt) != 30*time.Second {
		t.Fatalf("concurrent acks consumed the final guard: restored=%d stuck=%v", q.restoredPending, q.StuckFor(observedAt))
	}
	pr58Writer(ins, q, stats).WriteBatch(context.Background(), inFlight[writers])
	if q.restoredPending != 0 || q.StuckFor(observedAt) != 0 {
		t.Fatalf("final ack did not clear startup guard: restored=%d stuck=%v", q.restoredPending, q.StuckFor(observedAt))
	}
}
