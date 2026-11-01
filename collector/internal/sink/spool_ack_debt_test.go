package sink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// Move only an isolated test spool, after Pop has loaded the batch. Keeping
// the directory unavailable also exercises retryAcks' ENOENT directory check.
func pr59OfflineSpool(t *testing.T, q *Queue) func() {
	t.Helper()
	dir, offline := q.spool.dir, q.spool.dir+"-offline"
	if err := os.Rename(dir, offline); err != nil {
		t.Fatal(err)
	}
	moved := true
	restore := func() {
		t.Helper()
		if moved {
			if err := os.Rename(offline, dir); err != nil {
				t.Fatal(err)
			}
			moved = false
		}
	}
	t.Cleanup(restore)
	return restore
}

func TestPR59AckDebtRetrySettlesOnlyItsOwnBatch(t *testing.T) {
	for _, alreadyRemoved := range []bool{false, true} {
		t.Run(fmt.Sprintf("already_removed=%t", alreadyRemoved), func(t *testing.T) {
			q, stats := pr58RestoredQueue(t, []any{ev("accepted")}, []any{ev("still-pending")})
			b := pr50ReviewPop(t, q)
			used := q.SpoolBytes()
			ins := &mockCH{}
			w := pr58Writer(ins, q, stats)
			restore := pr59OfflineSpool(t, q)
			w.WriteBatch(context.Background(), b)
			for i := 0; i < 8; i++ {
				q.retryAcks()
			}
			if len(q.ackDebt) != 1 || q.SpoolBytes() != used || q.restoredPending != 2 {
				t.Fatalf("unavailable directory must retain exactly one debt without settling: debt=%d used=%d restored=%d",
					len(q.ackDebt), q.SpoolBytes(), q.restoredPending)
			}
			restore()
			if alreadyRemoved {
				// ENOENT while the directory is available may settle the debt.
				if err := os.Remove(b.file); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 8; i++ {
				q.retryAcks()
			}
			if len(q.ackDebt) != 0 || q.SpoolBytes() != used-b.diskSize || q.restoredPending != 1 {
				t.Fatalf("retries must release just the accepted batch: debt=%d used=%d restored=%d",
					len(q.ackDebt), q.SpoolBytes(), q.restoredPending)
			}
			if ins.rows() != 1 || q.StuckFor(q.startedAt.Add(time.Minute)) != time.Minute {
				t.Fatal("ack retry resent data or cleared the other restored batch's guard")
			}
			w.WriteBatch(context.Background(), pr50ReviewPop(t, q))
			if ins.rows() != 2 || q.SpoolBytes() != 0 || q.restoredPending != 0 {
				t.Fatal("final ack must release the remaining capacity and startup guard")
			}
		})
	}
}

// Successful unlink followed by a directory-sync error must not be settled
// again. A POSIX write/search-only directory injects the post-unlink error.
func TestPR59AckDebtDirectorySyncErrorDoesNotDoubleSettle(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(fmt.Sprintf("deferred=%t", deferred), func(t *testing.T) {
			q, stats := pr58RestoredQueue(t, []any{ev("accepted")}, []any{ev("still-pending")})
			b := pr50ReviewPop(t, q)
			remainingBytes := q.SpoolBytes() - b.diskSize
			ins := &mockCH{}
			w := pr58Writer(ins, q, stats)
			if deferred {
				restore := pr59OfflineSpool(t, q)
				w.WriteBatch(context.Background(), b)
				restore()
				if len(q.ackDebt) != 1 {
					t.Fatal("fixture must create one deferred ack")
				}
			}
			dir := q.spool.dir
			t.Cleanup(func() {
				if err := os.Chmod(dir, 0700); err != nil {
					t.Errorf("restore spool permissions: %v", err)
				}
			})
			if err := os.Chmod(dir, 0300); err != nil {
				t.Fatal(err)
			}
			if f, err := os.Open(dir); err == nil {
				_ = f.Close()
				t.Skip("runner bypasses directory read permissions; cannot inject syncDir open failure")
			} else if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("unexpected directory-open error: %v", err)
			}
			if deferred {
				q.retryAcks()
			} else {
				w.WriteBatch(context.Background(), b)
			}
			if _, err := os.Stat(b.file); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unlink must succeed before the sync error: stat=%v", err)
			}
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 4; i++ {
				q.retryAcks()
			}
			if q.SpoolBytes() != remainingBytes || q.restoredPending != 1 || len(q.ackDebt) != 0 {
				t.Fatalf("post-unlink sync error must settle only once: used=%d want=%d restored=%d debt=%d",
					q.SpoolBytes(), remainingBytes, q.restoredPending, len(q.ackDebt))
			}
			w.WriteBatch(context.Background(), pr50ReviewPop(t, q))
			if ins.rows() != 2 || q.SpoolBytes() != 0 || q.restoredPending != 0 {
				t.Fatal("sync fault or its retry changed another batch's accounting")
			}
		})
	}
}

// A read-only directory allows Pop to load batches while every unlink fails.
// Concurrent writers must not lose debt, settle it twice, or duplicate it on
// each retry. Run with -race to include the shared counters and metric reads.
func TestPR59AckDebtConcurrentWritersAndPop(t *testing.T) {
	const batches, writers = 24, 4
	rows := make([][]any, batches)
	for i := range rows {
		rows[i] = []any{ev(fmt.Sprintf("accepted-%02d", i))}
	}
	q, stats := pr58RestoredQueue(t, rows...)
	used := q.SpoolBytes()
	q.spool.maxBytes = used
	dir := q.spool.dir
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Errorf("restore spool permissions: %v", err)
		}
	})
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	if f, err := os.CreateTemp(dir, ".permission-probe-"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skip("runner bypasses directory write permissions; cannot inject unlink failure")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unexpected permission-probe error: %v", err)
	}
	ins := &mockCH{}
	q.Close() // Pop drains existing batches and then terminates every writer.
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			pr58Writer(ins, q, stats).Run(context.Background())
		}()
	}
	close(start)
	for i := 0; i < 128; i++ {
		if q.SpoolBytes() != used || q.StuckFor(q.startedAt.Add(time.Minute)) != time.Minute {
			t.Error("failed unlinks must retain capacity and the startup guard")
			break
		}
		_ = q.Rows()
	}
	wg.Wait()
	if ins.rows() != batches || q.Rows() != 0 || len(q.ackDebt) != batches || q.restoredPending != batches || q.SpoolBytes() != used {
		t.Fatalf("each delivered batch must have exactly one outstanding ack: inserted=%d queued=%d debt=%d restored=%d used=%d",
			ins.rows(), q.Rows(), len(q.ackDebt), q.restoredPending, q.SpoolBytes())
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				q.retryAcks()
				_ = q.SpoolBytes()
				_ = q.StuckFor(q.startedAt.Add(time.Minute))
			}
		}()
	}
	wg.Wait()
	if ins.rows() != batches || len(q.ackDebt) != 0 || q.SpoolBytes() != 0 || q.restoredPending != 0 {
		t.Fatalf("concurrent retries must settle once without reinsertion: inserted=%d debt=%d used=%d restored=%d",
			ins.rows(), len(q.ackDebt), q.SpoolBytes(), q.restoredPending)
	}
}

// Losing the in-memory debt on restart is compatible with at-least-once:
// the retained durable batch must be replayed, then acknowledged normally.
func TestPR59AckDebtRestartReplaysAcknowledgedInsert(t *testing.T) {
	q, stats := pr58RestoredQueue(t, []any{ev("accepted")})
	b := pr50ReviewPop(t, q)
	ins := &mockCH{}
	restore := pr59OfflineSpool(t, q)
	pr58Writer(ins, q, stats).WriteBatch(context.Background(), b)
	q.Close()
	restore()
	if ins.rows() != 1 || len(q.ackDebt) != 1 || q.SpoolBytes() != b.diskSize {
		t.Fatal("fixture must leave a delivered but unacknowledged durable batch")
	}
	restartedStats := &Stats{}
	restarted, err := NewDurableQueue(q.spool.dir, q.SpoolCapacityBytes(), restartedStats)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	if restarted.Rows() != 1 || restarted.SpoolBytes() != b.diskSize || restarted.restoredPending != 1 {
		t.Fatal("restart must restore the retained file and its accounting")
	}
	pr58Writer(ins, restarted, restartedStats).WriteBatch(context.Background(), pr50ReviewPop(t, restarted))
	if ins.rows() != 2 || restarted.SpoolBytes() != 0 || restarted.restoredPending != 0 {
		t.Fatal("at-least-once replay must finish with a single settlement in the new queue")
	}
}
