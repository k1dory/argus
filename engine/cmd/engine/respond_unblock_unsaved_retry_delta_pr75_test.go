package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// The late pass successfully removes a block, but fails to journal the manual
// decision. Following the API's own "repeat unblock" warning must acknowledge
// the successful durability repair even though no active block remains.
func TestDeltaPR75UnblockRetryAcknowledgesSavedLateDecision(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	ctx := context.Background()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-755", "203.0.113.7")}, time.Now().Add(-2*time.Hour))
	if keyState(e, "INC-755", "203.0.113.7") != keyFailed {
		t.Fatal("fixture: initial pending key is required")
	}
	x.available.Store(true)
	var startedLate, failedLate atomic.Bool
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
					t.Errorf("fixture: decode row: %v", err)
					http.Error(w, "fixture: invalid row", http.StatusBadRequest)
					return
				}
				if row.Step != stepManual {
					continue
				}
				if row.IncidentID == "INC-755" && startedLate.CompareAndSwap(false, true) {
					// This key appears after the initial operatorKeys snapshot, and
					// is already done when the handler reaches doneKeys/Unblock.
					e.autoRespond(r.Context(), []*incidents.Incident{capInc("INC-756", "203.0.113.7")}, time.Now())
				}
				if row.IncidentID == "INC-756" && failedLate.CompareAndSwap(false, true) {
					http.Error(w, "fixture: late journal write unavailable", http.StatusServiceUnavailable)
					return
				}
			}
		}
		f.srv.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(journal.Close)
	e.ch = store.New(journal.URL, "argus", "default", "")
	body := `{"ip":"203.0.113.7","user":"qa","reason":"reviewed false positive"}`
	code, out := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s", body)
	var first struct{ Warning string }
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatal(err)
	}
	k := e.keySnapshot(keyOf("INC-756", "203.0.113.7"))
	if code != http.StatusOK || first.Warning == "" || k == nil || !k.unsaved || len(e.resp.Active()) != 0 {
		t.Fatalf("fixture: expected successful unblock with unsaved late decision: HTTP %d %s; key=%+v", code, out, k)
	}
	code, out = do(t, e.handler(), http.MethodPost, "/respond/unblock", "s", body)
	if code != http.StatusOK {
		t.Errorf("the requested durability retry reported failure after saving the decision: HTTP %d %s", code, out)
	}
	saveJournal(f)
	restarted := keyEngine(t, f, x, 4)
	if !restarted.restoreKeys(ctx, time.Now()) || keyState(restarted, "INC-756", "203.0.113.7") != keyManual {
		t.Fatal("the repaired decision must survive restart")
	}
}
