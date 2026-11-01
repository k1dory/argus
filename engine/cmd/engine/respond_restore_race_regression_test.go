package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// After a failed startup read, loop can launch overlapping expireBlocks calls.
// A delayed SELECT must not restore an obsolete failed state over a successful
// retry, turn it into noop, and release that successful block's cap slot.
func TestPR67ConcurrentJournalRestoreKeepsSuccessfulBlockSlot(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	t0 := time.Now().UTC().Truncate(time.Second)
	beforeRestart := keyEngine(t, f, x, 1)
	beforeRestart.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	if x.calls.Load() != 1 || keyState(beforeRestart, "INC-1", "203.0.113.7") != keyFailed {
		t.Fatal("fixture: one failed, journaled attempt is required")
	}
	saveJournal(f)

	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseRead := func() { releaseOnce.Do(func() { close(release) }) }
	var reads atomic.Int32
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") != "" {
			f.srv.Config.Handler.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if !strings.Contains(string(body), "FROM response_log WHERE ip != ''") {
			f.srv.Config.Handler.ServeHTTP(w, r)
			return
		}
		// Capture the response before the successful retry's journal INSERTs.
		rec := httptest.NewRecorder()
		f.srv.Config.Handler.ServeHTTP(rec, r)
		if reads.Add(1) == 1 {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	t.Cleanup(journal.Close)
	t.Cleanup(releaseRead)
	e := keyEngine(t, f, x, 1)
	e.ch = store.New(journal.URL, "argus", "default", "")
	x.available.Store(true)
	now := t0.Add(61 * time.Second)
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(firstDone)
		e.expireBlocks(ctx, now)
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first journal read did not start")
	}
	go func() {
		defer close(secondDone)
		e.expireBlocks(ctx, now)
	}()
	select {
	case <-secondDone:
		// HEAD finishes the second restore and blocks before the first read returns.
	case <-time.After(time.Second):
		// Also permit a fix that serializes restoration and waits for the first read.
	}
	releaseRead()
	for _, done := range []<-chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-ctx.Done():
			t.Fatal("overlapping restoration did not finish")
		}
	}
	if x.blocks.Load() != 1 {
		t.Fatalf("fixture: restored retry should block exactly once, got %d", x.blocks.Load())
	}
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, now.Add(time.Second))
	if got := x.blocks.Load(); got != 1 {
		t.Fatalf("stale restore released a successful block's slot: %d blocks with block_cap=1 in the same /24 and window", got)
	}
}
