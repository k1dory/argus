package sink

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Once successful INSERTs have turned the entire spool into ack debt, there
// are no queued batches left to trigger WriteBatch's retryAcks. Recovery must
// still release capacity: otherwise Pop waits for Push while Push waits for
// an ack that can only run after Pop. Do not call retryAcks directly here.
func TestPR59AckDebtFullSpoolRecoversWithoutAnotherBatch(t *testing.T) {
	for _, restored := range []bool{false, true} {
		name := "new_batch"
		if restored {
			name = "restored_batch"
		}
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "spool")
			stats := &Stats{}
			q, err := NewDurableQueue(dir, 1<<20, stats)
			if err != nil {
				t.Fatal(err)
			}
			// Reuse the same payload so the next batch fits the configured
			// capacity exactly once the acknowledged file has been removed.
			rows := []any{ev("accepted")}
			if err := q.Push(rows); err != nil {
				t.Fatal(err)
			}
			capacity := q.SpoolBytes()
			if restored {
				q.Close()
				q, err = NewDurableQueue(dir, capacity, stats)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				q.spool.maxBytes = capacity
			}
			t.Cleanup(q.Close)
			b := pr50ReviewPop(t, q)
			if b.restored != restored {
				t.Fatal("fixture has the wrong startup accounting state")
			}

			// Pop has loaded the rows. Temporarily losing the directory now
			// fails only the unlink after INSERT, without losing fixture data.
			offline := dir + "-offline"
			if err := os.Rename(dir, offline); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := os.Stat(offline); err == nil {
					if err := os.Rename(offline, dir); err != nil {
						t.Errorf("restore spool fixture: %v", err)
					}
				}
			})
			ins := &mockCH{}
			w := NewWriter(ins, q, stats)
			w.Backoff, w.MaxBackoff = 5*time.Millisecond, 5*time.Millisecond
			w.WriteBatch(context.Background(), b)
			if ins.rows() != 1 || q.Rows() != 0 || q.SpoolBytes() != capacity || len(q.ackDebt) != 1 {
				t.Fatal("fixture must leave the full spool occupied only by a failed ack")
			}
			if err := os.Rename(offline, dir); err != nil {
				t.Fatal(err)
			}

			// This is the production consumer loop, including its blocking Pop.
			done := make(chan struct{})
			go func() {
				defer close(done)
				w.Run(context.Background())
			}()
			t.Cleanup(func() {
				q.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("writer did not exit after Close")
				}
			})

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := q.PushContext(ctx, rows); err != nil {
				t.Fatalf("disk recovered, but ack debt still blocks ingestion: PushContext=%v, used=%d/%d, pending_rows=%d, stuck=%v",
					err, q.SpoolBytes(), capacity, q.Rows(), q.StuckFor(q.startedAt.Add(time.Minute)))
			}
			q.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("writer did not drain the next accepted batch")
			}
			if ins.rows() != 2 || q.SpoolBytes() != 0 || q.restoredPending != 0 {
				t.Fatalf("recovery must settle both files without resending ack debt: inserted=%d used=%d restored=%d",
					ins.rows(), q.SpoolBytes(), q.restoredPending)
			}
		})
	}
}
