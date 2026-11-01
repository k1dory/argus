package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// The manual timestamp is captured before its INSERT completes. A new attempt
// can reserve and block during that INSERT, with a later journal timestamp.
// The successful cancellation clears both keys locally; restoration must not
// resurrect the later attempt's cap slot just because its timestamp is newer.
func TestPR75RestoreManualDecisionDoesNotResurrectLaterFlightSlot(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// A pending key whose cap slot is outside the 1h window lets the next
	// incident acquire the slot while the operator's journal write is pending.
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, time.Now().Add(-2*time.Hour))
	if keyState(e, "INC-1", "203.0.113.7") != keyFailed {
		t.Fatal("fixture: a pending failed attempt is required")
	}
	decisionSeen, release := make(chan time.Time, 1), make(chan struct{})
	var once sync.Once
	releaseWrite := func() { once.Do(func() { close(release) }) }
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "fixture: read request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT INTO response_log ") {
			for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
				var row store.ResponseRow
				if err := json.Unmarshal([]byte(line), &row); err != nil {
					t.Errorf("fixture: decode inserted row: %v", err)
					http.Error(w, "fixture: invalid row", http.StatusBadRequest)
					return
				}
				if row.Step != stepManual || row.IncidentID != "INC-1" {
					continue
				}
				at, err := time.ParseInLocation("2006-01-02 15:04:05", row.TS, time.UTC)
				if err != nil {
					t.Errorf("fixture: parse manual timestamp: %v", err)
					http.Error(w, "fixture: invalid timestamp", http.StatusBadRequest)
					return
				}
				decisionSeen <- at
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
		}
		f.srv.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(journal.Close)
	t.Cleanup(releaseWrite)
	e.ch = store.New(journal.URL, "argus", "default", "")
	type reply struct {
		code int
		body string
	}
	manualDone := make(chan reply, 1)
	go func() {
		code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
			`{"ip":"203.0.113.7","user":"qa","reason":"cancel this false positive"}`)
		manualDone <- reply{code, body}
	}()
	var decisionAt time.Time
	select {
	case decisionAt = <-decisionSeen:
	case <-ctx.Done():
		t.Fatal("manual decision did not reach the journal")
	}
	x.available.Store(true)
	// Logical cycle time models a journal delay across a second boundary;
	// channels, rather than a real sleep, control the request ordering.
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.7")}, decisionAt.Add(time.Second))
	if x.blocks.Load() != 1 || len(e.resp.Active()) != 1 {
		t.Fatal("fixture: the newer attempt must block before the manual INSERT finishes")
	}
	releaseWrite()
	select {
	case res := <-manualDone:
		if res.code != http.StatusOK {
			t.Fatalf("manual cancellation: HTTP %d %s", res.code, res.body)
		}
	case <-ctx.Done():
		t.Fatal("manual cancellation did not finish")
	}
	e.respMu.Lock()
	liveSlots := len(e.respSlots[capKey(respond.ModeIPS, "t-waf", "203.0.113.7")])
	e.respMu.Unlock()
	if liveSlots != 0 || len(e.resp.Active()) != 0 || keyState(e, "INC-2", "203.0.113.7") != keyManual {
		t.Fatal("fixture: cancellation must clear the newer block and its slot in memory")
	}
	saveJournal(f)
	restarted := keyEngine(t, f, x, 1)
	before := x.blocks.Load()
	restarted.autoRespond(ctx, []*incidents.Incident{capInc("INC-3", "203.0.113.8")}, decisionAt.Add(2*time.Minute))
	if x.blocks.Load() != before+1 || keyState(restarted, "INC-3", "203.0.113.8") != keyDone {
		t.Fatalf("restoration resurrected a cancelled slot: cancelled key=%q, next IP=%q, blocks=%d -> %d",
			keyState(restarted, "INC-2", "203.0.113.7"), keyState(restarted, "INC-3", "203.0.113.8"), before, x.blocks.Load())
	}
}
