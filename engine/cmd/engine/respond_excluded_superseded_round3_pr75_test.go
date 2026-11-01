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

// saveJournal ignores the SQL time windows. This fixture filters the recorded
// journal using the actual query's parameters and long-window step predicate,
// so it cannot accidentally restore a terminal row excluded by ResponsesSince.
func round3PR75JournalWithReadWindows(t *testing.T, f *fakeCH) *store.ClickHouse {
	t.Helper()
	// Long window: step=exclude rows and the whole history of keys that were ever
	// excluded within it (the subquery on (incident_id, ip)).
	longWindow := regexp.MustCompile(`(?s)ts\s*>=\s*\{exclude_since:DateTime\}\s+AND\s+\(step\s*=\s*'exclude'\s+OR\s+\(incident_id,\s*ip\)\s+IN\s+\(SELECT incident_id, ip FROM response_log WHERE step\s*=\s*'excluded'`)
	journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("fixture: read request: %v", err)
			http.Error(w, "fixture read failed", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if r.URL.Query().Get("query") != "" || !strings.Contains(string(body), "FROM response_log WHERE ip != ''") {
			f.srv.Config.Handler.ServeHTTP(w, r)
			return
		}
		since, excludeSince := r.URL.Query().Get("param_since"), r.URL.Query().Get("param_exclude_since")
		for _, bound := range []string{since, excludeSince} {
			if _, err := time.ParseInLocation("2006-01-02 15:04:05", bound, time.UTC); err != nil {
				t.Errorf("fixture: invalid time bound: %v", err)
				http.Error(w, "fixture time bound invalid", http.StatusBadRequest)
				return
			}
		}
		if !longWindow.MatchString(string(body)) {
			t.Error("fixture: update the time-window evaluator for the new SQL shape")
			http.Error(w, "fixture query unsupported", http.StatusBadRequest)
			return
		}
		var all []store.ResponseRow
		var lines []string
		excludedKey := map[[2]string]bool{}
		for _, line := range f.rows("response_log") {
			var row store.ResponseRow
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Errorf("fixture: invalid journal row: %v", err)
				return
			}
			all, lines = append(all, row), append(lines, line)
			if row.Step == "excluded" && row.TS >= excludeSince {
				excludedKey[[2]string{row.IncidentID, row.IP}] = true
			}
		}
		for i, row := range all {
			long := row.TS >= excludeSince && (row.Step == "exclude" || excludedKey[[2]string{row.IncidentID, row.IP}])
			if row.IP != "" && row.Step != "" && (row.TS >= since || long) {
				_, _ = io.WriteString(w, lines[i]+"\n")
			}
		}
	}))
	t.Cleanup(journal.Close)
	return store.New(journal.URL, "argus", "default", "")
}

// Reading excluded for longer than manual must not resurrect a superseded
// excluded state. An old terminal key may age out, but it must not turn back
// into the marker that bypasses restoreRespState's done guard on open incidents.
func TestRound3PR75LongWindowDoesNotResurrectSupersededExcludedKey(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	grantAt, manualAt := now.Add(-96*time.Hour), now.Add(-72*time.Hour)
	until := now.Add(-30 * time.Minute)
	grant := exclusion{at: grantAt, until: until}
	e.setExclusion("203.0.113.7", grant)
	if err := e.ch.InsertResponses(ctx, []store.ResponseRow{
		excludeRow("203.0.113.7", "qa", "multi-day scanner window", grantAt, until),
	}); err != nil {
		t.Fatal(err)
	}
	first := grantAt.Add(time.Minute)
	event := wafEvent(model.FormatTS(first), "203.0.113.7", "file", "")
	created, _, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{event}), first)
	if len(created) != 1 {
		t.Fatal("fixture: expected one open incident")
	}
	id := created[0].IncidentID
	e.autoRespond(ctx, snapshotIncidents(created), first)
	if keyState(e, id, "203.0.113.7") != keyExcluded {
		t.Fatal("fixture: the first decision must be excluded")
	}
	rows, keys, pending := e.operatorKeys("203.0.113.7", "qa", "cancel this incident's automatic block", manualAt)
	if len(keys) != 1 || pending != 1 {
		t.Fatal("fixture: the operator must cancel the excluded key")
	}
	if err := e.ch.InsertResponses(ctx, rows); err != nil {
		t.Fatal(err)
	}
	e.applyKeys(keys, manualAt, true)
	if keyState(e, id, "203.0.113.7") != keyManual || countSteps(f, stepManual) != 1 {
		t.Fatal("fixture: a newer durable manual decision must supersede excluded")
	}

	open := []incidents.Incident{*created[0]}
	restarted := keyEngine(t, f, x, 4)
	restarted.ch = round3PR75JournalWithReadWindows(t, f)
	restarted.reg = incidents.NewRegistry(1, open)
	restarted.restoreRespState(open, now)
	if !restarted.restoreKeys(ctx, now) {
		t.Fatal("fixture: restoration failed")
	}
	restoredState := keyState(restarted, id, "203.0.113.7")
	// Pruning does not repair this: the resurrected key inherits the exclusion's
	// recent until, even though its latest real decision was terminal/manual.
	restarted.pruneRespState(now, respStateTTL)
	fresh := wafEvent(model.FormatTS(now.Add(time.Minute)), "203.0.113.7", "file", "")
	created, updated, _ := restarted.reg.Apply(eval.Run(restarted.current(), []*model.Event{fresh}), now.Add(time.Minute))
	if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != id {
		t.Fatal("fixture: fresh evidence must update the same open incident")
	}
	restarted.autoRespond(ctx, snapshotIncidents(updated), now.Add(time.Minute))
	if x.blocks.Load() != 0 {
		t.Fatalf("selective history resurrected excluded and re-blocked a resolved open incident: restored=%q, blocks=%d, key=%q",
			restoredState, x.blocks.Load(), keyState(restarted, id, "203.0.113.7"))
	}
}
