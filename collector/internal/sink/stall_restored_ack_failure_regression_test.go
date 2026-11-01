package sink

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// An unlink failure must not strand restoredPending after the writer has
// delivered the batch and retired its only in-memory copy. After the spool
// becomes writable/available again, the same process must be able to settle
// startup recovery; otherwise an empty, healthy queue reports a stall forever.
func TestPR58RestoredAckFailureDoesNotStrandStartupGuard(t *testing.T) {
	for _, outcome := range []string{"insert", "dead_letter"} {
		t.Run(outcome, func(t *testing.T) {
			object := "accepted"
			if outcome == "dead_letter" {
				object = "poison"
			}
			q, stats := pr58RestoredQueue(t, []any{ev(object)})
			b := pr50ReviewPop(t, q)
			if !b.restored || q.restoredPending != 1 {
				t.Fatal("fixture must load one restored batch into the writer")
			}

			// Fault injection after Pop has loaded the rows: temporarily moving
			// the spool directory makes os.Remove fail without deleting data,
			// relying on timing, or requiring an unprivileged uid for chmod.
			// EACCES/EROFS in ack takes the same early-return path.
			dir, offline := q.spool.dir, q.spool.dir+"-offline"
			if err := os.Rename(dir, offline); err != nil {
				t.Fatal(err)
			}
			moved := true
			t.Cleanup(func() {
				if moved {
					if err := os.Rename(offline, dir); err != nil {
						t.Errorf("restore fixture spool: %v", err)
					}
				}
			})
			if _, err := os.Stat(b.file); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("fixture must make unlink fail: stat error=%v", err)
			}
			w := pr58Writer(&mockCH{}, q, stats)
			w.WriteBatch(context.Background(), b)
			if stats.Inserted.Load()+stats.DeadLetter.Load() != 1 || stats.RejectsFailed.Load() != 0 {
				t.Fatal("ClickHouse must resolve the batch before its spool ack fails")
			}
			if q.restoredPending != 1 || q.StuckFor(q.startedAt.Add(time.Minute)) == 0 {
				t.Error("failed ack must retain the startup guard until durable progress")
			}
			if err := os.Rename(offline, dir); err != nil {
				t.Fatal(err)
			}
			moved = false

			// A correct implementation can retain/requeue an unacknowledged
			// batch and finish its ack here. Do not manually ack the lost local
			// copy: production has no reference to it after WriteBatch returns.
			if err := q.Push([]any{ev("accepted-after-disk-recovery")}); err != nil {
				t.Fatal(err)
			}
			for pass := 0; pass < 4 && q.Rows() > 0; pass++ {
				w.WriteBatch(context.Background(), pr50ReviewPop(t, q))
			}
			if q.Rows() != 0 || stats.Inserted.Load() == 0 {
				t.Fatal("healthy writer must drain queued work after the filesystem recovers")
			}
			if got := q.StuckFor(q.startedAt.Add(20 * time.Minute)); got != 0 {
				t.Errorf("ack failure permanently stranded startup guard: stuck=%v restored=%d pending_rows=%d; want no stall after recovery",
					got, q.restoredPending, q.Rows())
			}
		})
	}
}
