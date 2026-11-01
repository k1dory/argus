package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/devitex-soft/argus/engine/internal/store"
)

// The initial reserve has a recorded failure, so it cannot represent an
// unconfirmed later attempt. Retry must first persist its own reserve and
// must not call the executor while response_log rejects INSERTs.
func TestPR49Round4RetryRequiresDurableReserve(t *testing.T) {
	f := newFakeCH(t)
	var available atomic.Bool
	var blocks atomic.Int32
	// Servers live outside the fake-clock bubble. Closing every connection
	// lets the client's network goroutines exit before advancing fake time.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Connection", "close")
		if req.URL.Path != "/block" {
			http.Error(w, "unexpected fixture path", http.StatusNotFound)
			return
		}
		if !available.Load() {
			http.Error(w, "fixture executor unavailable", http.StatusServiceUnavailable)
			return
		}
		blocks.Add(1)
	}))
	t.Cleanup(srv.Close)
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Connection", "close")
		f.srv.Config.Handler.ServeHTTP(w, req)
	}))
	t.Cleanup(journal.Close)

	synctest.Test(t, func(t *testing.T) {
		e := scanEngine(t, f, 1, ipsConfig(srv))
		e.ch = store.New(journal.URL, "argus", "default", "")
		now := time.Now()
		created, _ := e.applyEvents(pr49Round3Scan("203.0.113.7", 3, now.Add(-time.Second)), now)
		if len(created) != 1 {
			t.Fatal("fixture must create one collapsed incident")
		}
		e.autoRespond(context.Background(), snapshotIncidents(created), now)
		if blocks.Load() != 0 || e.resp.Pending() != 1 || len(f.rows("response_log")) != 3 {
			t.Fatal("fixture requires a reserve, a recorded executor failure and one queued retry")
		}
		f.mu.Lock()
		f.fail["response_log"] = true
		f.mu.Unlock()
		available.Store(true)
		time.Sleep(time.Minute + time.Second) // virtual time; no one-minute wall-clock wait
		e.expireBlocks(context.Background(), time.Now())
		if got := blocks.Load(); got != 0 {
			t.Fatalf("Retry executed %d block(s) while response_log rejected all INSERTs; journal still has only the first failed attempt's %d rows", got, len(f.rows("response_log")))
		}
	})
}
