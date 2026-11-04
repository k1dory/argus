package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

const pr115LifecycleQuery = "action IN ('engine.started', 'engine.stopped')"

// Install middleware before accepting requests, rather than mutating the
// Handler field of a running http.Server. Keep the existing fake's row store.
func pr115WrapLifecycleServer(t *testing.T, f *fakeCH, handler http.Handler) {
	t.Helper()
	f.srv.Close()
	f.srv = httptest.NewServer(handler)
	t.Cleanup(f.srv.Close)
}

// run now starts detection concurrently with announceStart. A slow history
// query must not leave that active run without a durable start marker: if it
// crashes before the SELECT finishes, the next run otherwise sees the older
// stopped marker and silently treats the crash as a clean restart.
func TestPR115ActiveRunHasStartMarkerDuringHistoryLookup(t *testing.T) {
	f := newFakeCH(t)
	f.selects[pr115LifecycleQuery] = `{"action":"engine.stopped","at":"2026-11-04 11:59:00.000"}`
	baseHandler := f.srv.Config.Handler
	lookupEntered := make(chan struct{})
	var firstLookup sync.Once
	pr115WrapLifecycleServer(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") == "" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "fixture body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			blocked := false
			if strings.Contains(string(body), pr115LifecycleQuery) {
				firstLookup.Do(func() {
					blocked = true
					close(lookupEntered)
				})
			}
			if blocked {
				<-r.Context().Done()
				return
			}
		}
		baseHandler.ServeHTTP(w, r)
	}))
	start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	counter := filepath.Join(t.TempDir(), "memory.events")
	if err := os.WriteFile(counter, []byte("oom_kill 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &engine{ch: store.New(f.srv.URL, "argus", "default", ""), cgroupEvents: counter}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.announceStart(ctx, start)
	}()
	select {
	case <-lookupEntered:
	case <-ctx.Done():
		t.Fatal("history lookup was not reached")
	}
	// At this point run() has already entered e.loop(). The history SELECT is
	// still pending, but a start marker must survive a crash of that loop.
	rowsBeforeCrash := lifecycleRows(t, f)
	if _, ok := rowsBeforeCrash["engine.started"]; !ok {
		t.Error("active detector has no durable engine.started while the history SELECT is pending")
	}
	// Model the in-flight HTTP work disappearing on an unclean process exit.
	// Deliberately do not call announceStop.
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("announceStart did not stop after cancellation")
	}
	// The next run sees only what was durable before the simulated crash.
	if started, ok := rowsBeforeCrash["engine.started"]; ok {
		row, err := json.Marshal(store.EngineLifecycle{
			Action: started.Action, At: started.TS, OOMKill: started.Attrs["oom_kill"],
		})
		if err != nil {
			t.Fatal(err)
		}
		f.mu.Lock()
		f.selects[pr115LifecycleQuery] = string(row)
		f.mu.Unlock()
	}
	next := &engine{ch: e.ch, cgroupEvents: counter}
	nextCtx, nextCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer nextCancel()
	next.announceStart(nextCtx, start.Add(time.Minute))
	if _, ok := lifecycleRows(t, f)["engine.restarted"]; !ok || next.m.uncleanRestarts.Load() != 1 {
		t.Fatal("crash during the background lookup was forgotten: the next run sees a clean stop")
	}
}

// The detector and the container healthcheck can run while history is being
// read. An OOM of another process during that read belongs to the current run,
// not to the previous exit. Both the reason and the started snapshot must use
// the counter captured before waiting for ClickHouse.
func TestPR115OOMSnapshotPrecedesHistoryLookup(t *testing.T) {
	for _, tc := range []struct {
		name, atStart, afterLookup, reason string
	}{
		{"oom_during_current_run", "7", "8", "unclean"},
		{"oom_before_current_run", "8", "8", "oom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCH(t)
			f.selects[pr115LifecycleQuery] = `{"action":"engine.started","at":"2026-11-04 11:00:00.000","oom_kill":"7"}`
			counter := filepath.Join(t.TempDir(), "memory.events")
			if err := os.WriteFile(counter, []byte("oom_kill "+tc.atStart+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			baseHandler := f.srv.Config.Handler
			pr115WrapLifecycleServer(t, f, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("query") == "" {
					// Deterministically place the counter change after the SELECT
					// was sent, but before announceStart receives its result.
					if err := os.WriteFile(counter, []byte("oom_kill "+tc.afterLookup+"\n"), 0o600); err != nil {
						t.Errorf("change fixture counter: %v", err)
						http.Error(w, "fixture counter", http.StatusInternalServerError)
						return
					}
				}
				baseHandler.ServeHTTP(w, r)
			}))
			e := &engine{ch: store.New(f.srv.URL, "argus", "default", ""), cgroupEvents: counter}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			e.announceStart(ctx, start)
			rows := lifecycleRows(t, f)
			started, haveStart := rows["engine.started"]
			restarted, haveRestart := rows["engine.restarted"]
			if !haveStart || !haveRestart || started.TS != model.FormatTS(start) {
				t.Fatalf("fixture: expected start and restart events: %+v", rows)
			}
			if got := started.Attrs["oom_kill"]; got != tc.atStart {
				t.Errorf("engine.started snapshot=%q, want counter at start=%q", got, tc.atStart)
			}
			if got := restarted.Attrs["reason"]; got != tc.reason {
				t.Errorf("previous exit reason=%q, want %q: an OOM during this run must not be attributed to the previous run", got, tc.reason)
			}
		})
	}
}
