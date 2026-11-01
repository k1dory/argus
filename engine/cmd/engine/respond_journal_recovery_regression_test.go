package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// Exercise real cycle/Registry.Apply delivery: an unchanged incident is not
// returned in created/updated again. Recovering journal reads must therefore
// replay deferred automatic responses without requiring another attack event.
func TestPR67JournalRecoveryRetriesDeferredIncidentWithoutNewEvents(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	x.entered = make(chan struct{}, 1)
	var readable atomic.Bool
	failedRead := make(chan struct{}, 1)
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("query") == "" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			if strings.Contains(string(body), "FROM response_log WHERE ip != ''") && !readable.Load() {
				http.Error(w, "Code: 241. DB::Exception: fixture read failure", http.StatusInternalServerError)
				select {
				case failedRead <- struct{}{}:
				default:
				}
				return
			}
		}
		f.srv.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(journal.Close)
	e := keyEngine(t, f, x, 1)
	e.ch = store.New(journal.URL, "argus", "default", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now()
	events := []*model.Event{wafEvent(model.FormatTS(now), "203.0.113.7", "file", "")}
	e.cycle(ctx, e.current(), events)
	select {
	case <-failedRead:
	case <-ctx.Done():
		t.Fatal("fixture: cycle did not create an eligible incident and try reading the journal")
	}
	if x.calls.Load() != 0 {
		t.Fatal("an unread journal must prevent executor calls")
	}
	readable.Store(true)
	e.expireBlocks(ctx, now.Add(30*time.Second))
	e.cycle(ctx, e.current(), events) // the same buffer, no new event
	select {
	case <-x.entered:
	case <-time.After(time.Second):
		t.Fatal("journal recovered, but the incident was discarded: no block on subsequent cycles without new events")
	}
}
