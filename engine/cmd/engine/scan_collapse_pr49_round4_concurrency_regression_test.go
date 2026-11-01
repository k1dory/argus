package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/store"
)

// cycle launches autoRespond asynchronously. Hold its first reserve INSERT,
// then let the next cycle finish the same address. The first call must not
// return the second call's occupied slot, on either INSERT success or failure.
func TestPR49Round4OverlappingReserveCannotReleaseSuccessfulBlockSlot(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		name := "first_insert_succeeds"
		if failFirst {
			name = "first_insert_fails"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			e := scanEngine(t, f, 1, ipsConfig(srv))
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			const ip = "203.0.113.7"
			created, _ := e.applyEvents(pr49Round3Scan(ip, 3, now.Add(-time.Second)), now)
			if len(created) != 1 {
				t.Fatal("fixture must create one collapsed incident")
			}
			id := created[0].IncidentID
			firstSnapshot := snapshotIncidents(created)
			_, updated := e.applyEvents(pr49Round3Scan(ip, 4, now.Add(30*time.Second)), now.Add(31*time.Second))
			if len(updated) != 1 || updated[0].IncidentID != id {
				t.Fatal("the second cycle must update the same incident")
			}
			secondSnapshot := snapshotIncidents(updated)

			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var reserves atomic.Int32
			journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				body, err := io.ReadAll(req.Body)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				_ = req.Body.Close()
				req.Body = io.NopCloser(strings.NewReader(string(body)))
				var row store.ResponseRow
				if strings.HasPrefix(req.URL.Query().Get("query"), "INSERT INTO response_log ") && json.Unmarshal(body, &row) == nil && strings.HasPrefix(row.Detail, reservePrefix) && reserves.Add(1) == 1 {
					close(entered)
					<-release
					if failFirst {
						http.Error(w, "fixture first reserve failure", http.StatusServiceUnavailable)
						return
					}
				}
				f.srv.Config.Handler.ServeHTTP(w, req)
			}))
			t.Cleanup(journal.Close)
			t.Cleanup(unblock)
			e.ch = store.New(journal.URL, "argus", "default", "")
			firstDone, secondDone := make(chan struct{}), make(chan struct{})
			go func() {
				e.autoRespond(context.Background(), firstSnapshot, now)
				close(firstDone)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first cycle did not reach reserve INSERT")
			}
			go func() {
				e.autoRespond(context.Background(), secondSnapshot, now.Add(31*time.Second))
				close(secondDone)
			}()
			select {
			case <-secondDone:
				// On the affected code this cycle already executed the block.
			case <-time.After(time.Second):
				// A fixed implementation may serialize the entire operation.
			}
			unblock()
			for _, done := range []<-chan struct{}{firstDone, secondDone} {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("autoRespond did not finish after releasing the INSERT")
				}
			}
			if got := blocks.Load(); got > 1 {
				t.Fatalf("the same address was blocked %d times", got)
			}
			before := blocks.Load()
			slots := len(e.respCap[id])
			_, updated = e.applyEvents(pr49Round3Scan("203.0.113.8", 3, now.Add(40*time.Second)), now.Add(41*time.Second))
			if len(updated) != 1 || updated[0].IncidentID != id {
				t.Fatal("the next address must join the same incident")
			}
			e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(41*time.Second))
			if got := blocks.Load(); got > 1 || (before == 1 && slots != 1) {
				t.Fatalf("an overlapping reserve released an applied block's slot: before=%d slots=%d after=%d, block_cap=1/1h", before, slots, got)
			}
		})
	}
}
