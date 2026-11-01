package sink

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

type pr50ReviewStallInserter struct {
	events func([]any) error
}

func (s pr50ReviewStallInserter) InsertEvents(_ context.Context, rows []any) error {
	return s.events(rows)
}

func (s pr50ReviewStallInserter) InsertRejects(context.Context, []Reject) error {
	return &Error{Table: "ingest_rejects", Status: 503}
}

func pr50ReviewPop(t *testing.T, q *Queue) Batch {
	t.Helper()
	// Do not let a missing requeue hang the regression test in Pop.
	if q.Rows() == 0 {
		t.Fatal("expected an unresolved batch in the queue")
	}
	b, ok := q.Pop()
	if !ok || b.loadErr != nil {
		t.Fatalf("pop: ok=%t err=%v", ok, b.loadErr)
	}
	return b
}

// Successful INSERTs are not forward progress for a durable batch when its
// smaller remainder cannot be saved: the same rows are reloaded next pass.
// Preserve the original stall age instead of signalling a false recovery.
func TestPR50ReviewFailedShrinkPreservesStall(t *testing.T) {
	st := &Stats{}
	q, err := NewDurableQueue(t.TempDir(), 1<<20, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("accepted"), ev("timeout")}); err != nil {
		t.Fatal(err)
	}
	partial := false
	ins := pr50ReviewStallInserter{events: func(rows []any) error {
		if !partial {
			return &Error{Table: "events", Status: 500, Code: 159}
		}
		if len(rows) > 1 {
			return &Error{Table: "events", Status: 500, Code: 241}
		}
		if rows[0].(model.Event).Object == "accepted" {
			return nil
		}
		return &Error{Table: "events", Status: 500, Code: 159}
	}}
	w := NewWriter(ins, q, st)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	t0 := time.Now()
	clock := t0
	w.Now = func() time.Time { return clock }
	b := pr50ReviewPop(t, q)
	before, err := os.ReadFile(b.file)
	if err != nil {
		t.Fatal(err)
	}
	w.WriteBatch(context.Background(), b)
	if got := q.StuckFor(t0.Add(time.Minute)); got != time.Minute {
		t.Fatalf("fixture must first establish a stalled batch: %v", got)
	}

	// Force os.CreateTemp in shrink to fail before replacing the batch, without
	// depending on chmod or the runner's uid. A regular file cannot be a temp
	// directory; b.file itself stays readable. ENOSPC/EROFS takes the same path.
	spoolDir := q.spool.dir
	q.spool.dir = b.file
	t.Cleanup(func() { q.spool.dir = spoolDir })
	partial = true
	for pass := 1; pass <= 2; pass++ {
		clock = t0.Add(time.Duration(10+pass) * time.Minute)
		w.WriteBatch(context.Background(), pr50ReviewPop(t, q))
		if q.Rows() != 2 {
			t.Fatalf("fixture must retain the entire batch after failed shrink: rows=%d", q.Rows())
		}
		after, err := os.ReadFile(b.file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatal("fixture must leave the original spool contents unchanged")
		}
		if got, want := q.StuckFor(clock), clock.Sub(t0); got != want {
			t.Errorf("failed shrink cleared the stall although the batch is unchanged: got=%v want=%v", got, want)
		}
		if got, want := st.StalledPasses.Load(), uint64(pass+1); got != want {
			t.Errorf("unchanged requeue was not counted: stalled_passes=%d want=%d", got, want)
		}
	}
	if st.Inserted.Load() != 2 {
		t.Fatalf("fixture must reinsert the same accepted row on both passes: inserted=%d", st.Inserted.Load())
	}
}

// Positive control for the no-progress path: group error 241 plus singleton
// timeout 159 must retain the same spool file, not rewrite identical contents.
func TestPR50ReviewNoProgressDoesNotRewriteSpool(t *testing.T) {
	st := &Stats{}
	q, err := NewDurableQueue(t.TempDir(), 1<<20, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("first"), ev("second")}); err != nil {
		t.Fatal(err)
	}
	ins := pr50ReviewStallInserter{events: func(rows []any) error {
		if len(rows) > 1 {
			return &Error{Table: "events", Status: 500, Code: 241}
		}
		return &Error{Table: "events", Status: 500, Code: 159}
	}}
	w := NewWriter(ins, q, st)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	t0 := time.Now()
	clock := t0
	w.Now = func() time.Time { return clock }
	b := pr50ReviewPop(t, q)
	beforeInfo, err := os.Stat(b.file)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(b.file)
	if err != nil {
		t.Fatal(err)
	}
	for pass := 0; pass < 2; pass++ {
		if pass > 0 {
			b = pr50ReviewPop(t, q)
		}
		clock = t0.Add(time.Duration(pass) * time.Minute)
		w.WriteBatch(context.Background(), b)
	}
	afterInfo, err := os.Stat(b.file)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(b.file)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(beforeInfo, afterInfo) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) || !bytes.Equal(before, after) {
		t.Error("a pass without fewer unresolved rows rewrote the spool file")
	}
	if q.Rows() != 2 || q.SpoolBytes() != int64(len(before)) || st.Inserted.Load() != 0 || st.DeadLetter.Load() != 0 {
		t.Fatalf("no progress must preserve all pending data: rows=%d bytes=%d stats=%+v", q.Rows(), q.SpoolBytes(), st)
	}
	if st.StalledPasses.Load() != 2 || q.StuckFor(clock) != time.Minute {
		t.Fatalf("unchanged requeues must preserve the first mark: passes=%d stuck=%v", st.StalledPasses.Load(), q.StuckFor(clock))
	}
}
