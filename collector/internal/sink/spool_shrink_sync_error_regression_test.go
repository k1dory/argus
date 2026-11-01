package sink

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// On POSIX, a write/search-only directory permits creating and renaming a file,
// but not opening the directory read-only for syncDir. This injects a real error
// AFTER shrink has replaced the batch, without modifying production functions.
// A privileged runner that bypasses directory permissions cannot use this seam.
func TestPR43ReviewShrinkSyncErrorReconcilesPublishedRemainder(t *testing.T) {
	dir := t.TempDir()
	st := &Stats{}
	q, err := NewDurableQueue(dir, 1<<20, st)
	if err != nil {
		t.Fatal(err)
	}
	large := ev("fine")
	large.Raw = strings.Repeat("x", 32<<10)
	if err := q.Push([]any{large, ev("poison")}); err != nil {
		t.Fatal(err)
	}
	b, ok := q.Pop()
	if !ok || b.loadErr != nil {
		t.Fatalf("cannot load fixture batch: ok=%t err=%v", ok, b.loadErr)
	}
	q.spool.maxBytes = b.diskSize // Only shrinking the accepted row frees capacity.

	t.Cleanup(func() {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Errorf("restore spool directory permissions: %v", err)
		}
	})
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	f, openErr := os.Open(dir)
	if openErr == nil {
		_ = f.Close()
		t.Skip("runner can open a directory without read permission; post-rename sync fault cannot be injected")
	}
	if !errors.Is(openErr, os.ErrPermission) {
		t.Fatalf("unexpected fault-injection prerequisite: %v", openErr)
	}

	ins := &mockCH{noTable: true}
	w := NewWriter(ins, q, st)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	w.WriteBatch(context.Background(), b)
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}

	remaining, err := readSpoolBatch(b.file)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].(model.Event).Object != "poison" {
		t.Fatalf("fixture did not reach the post-rename failure: remaining=%v", remaining)
	}
	info, err := os.Stat(b.file)
	if err != nil {
		t.Fatal(err)
	}
	if ins.rows() != 1 || st.RejectsFailed.Load() != 1 {
		t.Fatalf("fixture must insert the large row and retain the failed reject: inserted=%d failed=%d", ins.rows(), st.RejectsFailed.Load())
	}
	if used := q.SpoolBytes(); used != info.Size() {
		t.Errorf("rename published a smaller file but used retained the original size: used=%d actual=%d", used, info.Size())
	}
	if q.Rows() != 1 || q.Bytes() != SizeOf(remaining) {
		t.Errorf("requeued metadata describes the replaced batch: rows=%d bytes=%d, want 1/%d", q.Rows(), q.Bytes(), SizeOf(remaining))
	}

	// Permission recovery must also recover ingestion capacity. The failed reject
	// can remain unresolved indefinitely; it must not reserve the accepted row's
	// 32 KiB forever. No reader runs in parallel with this producer.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := q.PushContext(ctx, []any{ev("next")}); err != nil {
		t.Errorf("reclaimed disk space remains unavailable after the sync fault clears: %v", err)
	}
	q.Close()
	for next, ok := q.Pop(); ok; next, ok = q.Pop() {
		if next.loadErr != nil {
			t.Fatal(next.loadErr)
		}
		info, err := os.Stat(next.file)
		if err != nil {
			t.Fatal(err)
		}
		if next.diskSize != info.Size() || next.Count != len(next.Rows) {
			t.Errorf("reader received stale metadata: size=%d/%d count=%d/%d", next.diskSize, info.Size(), next.Count, len(next.Rows))
		}
		if err := q.ack(next); err != nil {
			t.Fatal(err)
		}
	}
	if q.SpoolBytes() != 0 {
		t.Errorf("ack of reconciled batches corrupted accounting: used=%d", q.SpoolBytes())
	}
}
