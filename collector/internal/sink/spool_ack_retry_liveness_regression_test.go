package sink

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The warning is emitted after retryAcks has detached the debt and processed
// every unlink, but before it puts failed unlinks back. Blocking just this
// fixture's warning gives the timer a deterministic view of an in-flight retry
// without replacing production functions or depending on filesystem speed.
type pr59AckRetryPauseHandler struct {
	slog.Handler
	dir     string
	entered chan struct{}
	resume  <-chan struct{}
	once    sync.Once
}

func (h *pr59AckRetryPauseHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *pr59AckRetryPauseHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Message == "spool: fsync каталога после отложенного подтверждения не удался" {
		matching := false
		r.Attrs(func(a slog.Attr) bool {
			if a.Key == "err" {
				err, _ := a.Value.Any().(error)
				var pathErr *os.PathError
				matching = errors.As(err, &pathErr) && pathErr.Path == h.dir
			}
			return !matching
		})
		if matching {
			h.once.Do(func() { close(h.entered) })
			<-h.resume
		}
	}
	return h.Handler.Handle(ctx, r)
}

// An empty ackDebt slice is not proof that all acknowledgements have settled:
// a concurrent retry can own the slice and later return failed unlinks. The
// queue must still recover on its own when no more batches arrive. In contrast,
// the full-spool regression supplies another PushContext, which can rescue an
// orphaned debt via persist even after the background loop has stopped.
func TestPR59AckRetryLoopSurvivesConcurrentRetryReturningDebt(t *testing.T) {
	q, stats := pr58RestoredQueue(t, []any{ev("accepted-first")}, []any{ev("accepted-second")})
	first, second := pr50ReviewPop(t, q), pr50ReviewPop(t, q)
	dir := q.spool.dir

	// Reserve timer ownership, then start the real ackRetryLoop below. This
	// models delayed scheduling of the goroutine started by ack and keeps the
	// timer from racing the filesystem fault setup itself.
	q.mu.Lock()
	q.ackRetrying = true
	q.mu.Unlock()

	previousLogger := slog.Default()
	resume := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	retryDone, loopDone := make(chan struct{}), make(chan struct{})
	retryStarted, loopStarted := false, false
	t.Cleanup(func() {
		q.Close()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Errorf("restore spool permissions: %v", err)
		}
		release()
		for _, worker := range []struct {
			name    string
			started bool
			done    <-chan struct{}
		}{
			{"foreground retry", retryStarted, retryDone},
			{"background loop", loopStarted, loopDone},
		} {
			if worker.started {
				select {
				case <-worker.done:
				case <-time.After(3 * ackRetryEvery):
					t.Errorf("%s did not exit after Close", worker.name)
				}
			}
		}
		slog.SetDefault(previousLogger)
	})

	restore := pr59OfflineSpool(t, q)
	ins := &mockCH{}
	w := pr58Writer(ins, q, stats)
	w.WriteBatch(context.Background(), first)
	w.WriteBatch(context.Background(), second)
	restore()
	q.mu.Lock()
	debtCount := len(q.ackDebt)
	q.mu.Unlock()
	if debtCount != 2 || ins.rows() != 2 || q.Rows() != 0 {
		t.Fatal("fixture must contain exactly two delivered batches with failed acks")
	}

	// Keep one real batch safe while making its old pathname unremovable. A
	// nonempty directory yields an unlink/rmdir error even for privileged users.
	// The other batch can be removed, so retryAcks will also attempt syncDir.
	saved := second.file + ".saved"
	if err := os.Rename(second.file, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second.file, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(second.file, "keep")
	if err := os.WriteFile(marker, []byte("unlink fault"), 0600); err != nil {
		t.Fatal(err)
	}
	// Write/search without read permits unlink but fails syncDir's os.Open.
	if err := os.Chmod(dir, 0300); err != nil {
		t.Fatal(err)
	}
	if f, err := os.Open(dir); err == nil {
		_ = f.Close()
		t.Skip("runner bypasses directory read permissions; cannot pause the sync-error path")
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("unexpected directory-open error: %v", err)
	}
	paused := &pr59AckRetryPauseHandler{
		Handler: previousLogger.Handler(), dir: dir,
		entered: make(chan struct{}), resume: resume,
	}
	slog.SetDefault(slog.New(paused))
	retryStarted = true
	go func() {
		defer close(retryDone)
		q.retryAcks()
	}()
	select {
	case <-paused.entered:
	case <-retryDone:
		t.Fatal("foreground retry did not reach the fault-injection barrier")
	case <-time.After(3 * time.Second):
		t.Fatal("foreground retry did not reach the fault-injection barrier in time")
	}
	if got := q.SpoolBytes(); got != second.diskSize {
		t.Fatalf("only the first ack should have settled: used=%d want=%d", got, second.diskSize)
	}

	loopStarted = true
	go func() {
		defer close(loopDone)
		q.ackRetryLoop()
	}()
	// Let the timer encounter the suspended foreground retry. A fix may keep
	// the loop alive, serialize retries, or restart it when failed debt returns.
	stoppedDuringRetry := false
	select {
	case <-loopDone:
		stoppedDuringRetry = true
	case <-time.After(2 * ackRetryEvery):
	}

	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(second.file); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(saved, second.file); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-retryDone:
	case <-time.After(3 * time.Second):
		t.Fatal("foreground retry did not finish after release")
	}

	// No Push, WriteBatch, or explicit retryAcks is allowed to rescue recovery.
	deadline := time.Now().Add(2*ackRetryEvery + 500*time.Millisecond)
	for q.SpoolBytes() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	q.mu.Lock()
	used, restored, debt, retrying := q.spool.used, q.restoredPending, len(q.ackDebt), q.ackRetrying
	q.mu.Unlock()
	stuck := q.StuckFor(q.startedAt.Add(time.Minute))
	if used != 0 || restored != 0 || debt != 0 || stuck != 0 {
		t.Fatalf("concurrent retry stranded ack debt after disk recovery: used=%d restored=%d debt=%d retrying=%t stopped_during_retry=%t stuck=%v",
			used, restored, debt, retrying, stoppedDuringRetry, stuck)
	}
	if ins.rows() != 2 || q.Rows() != 0 {
		t.Fatal("ack recovery must neither resend delivered rows nor requeue them")
	}
	if _, err := os.Stat(second.file); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("settled debt must remove the second spool file: stat=%v", err)
	}
}

// Unlike the full-spool regression, these cases never supply another producer
// or writer call after the failed ack. They exercise automatic timer startup,
// idle recovery, and termination with an unrecoverable debt after Close.
func TestPR59AckRetryLoopIdleRecoveryAndClose(t *testing.T) {
	for _, name := range []string{"idle_recovery", "close_with_debt"} {
		t.Run(name, func(t *testing.T) {
			q, stats := pr58RestoredQueue(t, []any{ev("accepted")})
			b := pr50ReviewPop(t, q)
			restore := pr59OfflineSpool(t, q)
			ins := &mockCH{}
			pr58Writer(ins, q, stats).WriteBatch(context.Background(), b)
			closed := name == "close_with_debt"
			if closed {
				q.Close()
			} else {
				restore()
			}
			deadline := time.Now().Add(2*ackRetryEvery + 500*time.Millisecond)
			for {
				q.mu.Lock()
				retrying := q.ackRetrying
				q.mu.Unlock()
				if !retrying {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("ack retry loop did not finish after recovery or Close")
				}
				time.Sleep(10 * time.Millisecond)
			}
			q.mu.Lock()
			used, restored, debt := q.spool.used, q.restoredPending, len(q.ackDebt)
			q.mu.Unlock()
			if closed {
				if used != b.diskSize || restored != 1 || debt != 1 {
					t.Fatalf("Close must preserve an unsettled file's accounting: used=%d restored=%d debt=%d", used, restored, debt)
				}
			} else if used != 0 || restored != 0 || debt != 0 || q.StuckFor(q.startedAt.Add(time.Minute)) != 0 {
				t.Fatalf("idle timer failed to settle ack debt: used=%d restored=%d debt=%d", used, restored, debt)
			}
			if ins.rows() != 1 || q.Rows() != 0 {
				t.Fatal("background ack must neither resend nor requeue the batch")
			}
		})
	}
}
