package sink

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Model an INSERT that exceeds its memory budget above two rows. All individual
// events are valid; writing them to ingest_rejects loses them to SIEM consumers.
type pr43SizeLimitedInserter struct {
	accepted map[string]int
	rejected []Reject
}

func (s *pr43SizeLimitedInserter) InsertEvents(_ context.Context, rows []any) error {
	if len(rows) > 2 {
		return &Error{Table: "events", Status: 500, Code: 241, Msg: "Memory limit exceeded"}
	}
	for _, row := range rows {
		s.accepted[row.(model.Event).Object]++
	}
	return nil
}

func (s *pr43SizeLimitedInserter) InsertRejects(_ context.Context, rows []Reject) error {
	s.rejected = append(s.rejected, rows...)
	return nil
}

// main.go always uses NewDurableQueue. The memory queue is a positive control:
// PR #43 must recover the same valid events through the actual spool path.
func TestPR43DurableQueueBisectsSizeErrors(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprintf("durable=%t", durable), func(t *testing.T) {
			stats := &Stats{}
			queue := NewQueue(100, stats)
			if durable {
				var err error
				queue, err = NewDurableQueue(t.TempDir(), 1<<20, stats)
				if err != nil {
					t.Fatal(err)
				}
			}
			var rows []any
			for i := 0; i < 8; i++ {
				e := model.Event{Source: "pr43-size", Object: fmt.Sprintf("valid-%d", i)}
				e.Ensure()
				rows = append(rows, e)
			}
			if err := queue.Push(rows); err != nil {
				t.Fatal(err)
			}
			queue.Close() // Pop must not block if the fixture is broken.
			batch, ok := queue.Pop()
			if !ok || batch.loadErr != nil || len(batch.Rows) != len(rows) {
				t.Fatalf("cannot read queued batch: ok=%t rows=%d err=%v", ok, len(batch.Rows), batch.loadErr)
			}
			if durable && (batch.file == "" || queue.SpoolBytes() == 0) {
				t.Fatal("fixture did not exercise the disk spool")
			}
			ins := &pr43SizeLimitedInserter{accepted: make(map[string]int)}
			writer := NewWriter(ins, queue, stats)
			writer.Attempts = 1
			writer.Sleep = func(context.Context, time.Duration) bool {
				t.Fatal("size-dependent errors must not need transport retries")
				return false
			}
			writer.WriteBatch(context.Background(), batch)
			for _, row := range rows {
				id := row.(model.Event).Object
				if got := ins.accepted[id]; got != 1 {
					t.Errorf("%s inserted %d times, want once; rejects=%d spool_bytes=%d", id, got, len(ins.rejected), queue.SpoolBytes())
				}
			}
			if len(ins.rejected) != 0 || stats.DeadLetter.Load() != 0 || stats.Inserted.Load() != uint64(len(rows)) {
				t.Errorf("valid batch discarded: inserted=%d dead=%d rejects=%d", stats.Inserted.Load(), stats.DeadLetter.Load(), len(ins.rejected))
			}
			if queue.Rows() != 0 || queue.SpoolBytes() != 0 {
				t.Errorf("successfully split batch must be acknowledged: pending=%d spool_bytes=%d", queue.Rows(), queue.SpoolBytes())
			}
		})
	}
}
