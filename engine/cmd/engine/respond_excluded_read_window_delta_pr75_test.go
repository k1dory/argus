package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// saveJournal normally returns every inserted row, ignoring ResponsesSince's
// WHERE clause. This fixture also enforces the two actual SELECT time windows:
// a key older than 48h must not magically reappear from that fake response.
// Both equality and IN predicates for the longer-lived steps are supported.
func TestDeltaPR75LongExcludedKeySurvivesRestartReadWindow(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	first := now.Add(-72 * time.Hour)
	until := now.Add(30 * time.Minute)
	e.setExclusion("203.0.113.7", exclusion{at: first, until: until})
	if err := e.ch.InsertResponses(ctx, []store.ResponseRow{
		excludeRow("203.0.113.7", "qa", "multi-day scanner window", first, until),
	}); err != nil {
		t.Fatal(err)
	}
	event := wafEvent(model.FormatTS(first), "203.0.113.7", "file", "")
	created, _, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{event}), first)
	if len(created) != 1 {
		t.Fatal("fixture: expected one incident")
	}
	id := created[0].IncidentID
	e.autoRespond(ctx, snapshotIncidents(created), first)
	if keyState(e, id, "203.0.113.7") != keyExcluded || x.blocks.Load() != 0 {
		t.Fatal("fixture: incident must be excluded initially")
	}
	journalRows := f.rows("response_log")
	longWindow := regexp.MustCompile(`(?s)OR\s+\((.*?)\s+AND\s+ts\s*>=\s*\{exclude_since:DateTime\}`)
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "fixture: read request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if r.URL.Query().Get("query") != "" || !strings.Contains(string(body), "FROM response_log WHERE ip != ''") {
			f.srv.Config.Handler.ServeHTTP(w, r)
			return
		}
		since, err := time.ParseInLocation("2006-01-02 15:04:05", r.URL.Query().Get("param_since"), time.UTC)
		if err != nil {
			t.Errorf("fixture: invalid since: %v", err)
			http.Error(w, "fixture: invalid since", http.StatusBadRequest)
			return
		}
		excludeSince, err := time.ParseInLocation("2006-01-02 15:04:05", r.URL.Query().Get("param_exclude_since"), time.UTC)
		if err != nil {
			t.Errorf("fixture: invalid exclude_since: %v", err)
			http.Error(w, "fixture: invalid exclude_since", http.StatusBadRequest)
			return
		}
		longSteps := longWindow.FindStringSubmatch(string(body))
		if len(longSteps) != 2 {
			t.Error("fixture: update the SELECT predicate fixture for the new query shape")
			http.Error(w, "fixture: unknown SELECT predicate", http.StatusBadRequest)
			return
		}
		for _, line := range journalRows {
			var row store.ResponseRow
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Errorf("fixture: decode row: %v", err)
				continue
			}
			at, err := time.ParseInLocation("2006-01-02 15:04:05", row.TS, time.UTC)
			if err != nil {
				t.Errorf("fixture: invalid row timestamp: %v", err)
				continue
			}
			if row.Step != "" && (!at.Before(since) ||
				(strings.Contains(longSteps[1], "'"+row.Step+"'") && !at.Before(excludeSince))) {
				_, _ = io.WriteString(w, line+"\n")
			}
		}
	}))
	t.Cleanup(journal.Close)
	open := []incidents.Incident{*created[0]}
	restarted := keyEngine(t, f, x, 4)
	restarted.ch = store.New(journal.URL, "argus", "default", "")
	restarted.reg = incidents.NewRegistry(1, open)
	restarted.restoreRespState(open, now)
	if !restarted.restoreKeys(ctx, now) {
		t.Fatal("fixture: journal restoration failed")
	}
	if _, excluded := restarted.excludedUntil("203.0.113.7", now); !excluded {
		t.Fatal("fixture: the address exclusion must still be active on restart")
	}
	after := until.Add(time.Minute)
	restarted.pruneRespState(after, respStateTTL)
	fresh := wafEvent(model.FormatTS(after), "203.0.113.7", "file", "")
	created, updated, _ := restarted.reg.Apply(eval.Run(restarted.current(), []*model.Event{fresh}), after)
	if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != id {
		t.Fatal("fixture: fresh evidence must update the same open incident")
	}
	restarted.autoRespond(ctx, snapshotIncidents(updated), after)
	if x.blocks.Load() != 1 {
		t.Fatalf("restart forgot the old excluded key and kept suppressing fresh evidence after expiry: incident=%q, key=%q, blocks=%d",
			restarted.respStatus(id), keyState(restarted, id, "203.0.113.7"), x.blocks.Load())
	}
}
