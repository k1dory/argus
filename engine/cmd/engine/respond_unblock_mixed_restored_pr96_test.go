package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/store"
)

type pr96JournalTransport func(*http.Request) (*http.Response, error)

func (f pr96JournalTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Only the HTTP transport is replaced: restoreKeys, the journal decoder and
// the unblock handler are real. All rows are inside the short read window.
// The tests are sequential because they replace http.DefaultTransport.
func pr96RestoredEngine(t *testing.T, rows []store.ResponseRow, now time.Time) *engine {
	t.Helper()
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	http.DefaultTransport = pr96JournalTransport(func(r *http.Request) (*http.Response, error) {
		defer r.Body.Close()
		if r.URL.Host != "pr96-journal.invalid" {
			return nil, fmt.Errorf("fixture: unexpected host %s", r.URL.Host)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		var out strings.Builder
		switch query := r.URL.Query().Get("query"); {
		case strings.HasPrefix(query, "INSERT INTO response_log "):
			dec := json.NewDecoder(strings.NewReader(string(body)))
			for {
				var row store.ResponseRow
				if err := dec.Decode(&row); err == io.EOF {
					break
				} else if err != nil {
					return nil, err
				}
				rows = append(rows, row)
			}
		case query == "" && strings.Contains(string(body), "FROM response_log WHERE ip != ''"):
			for _, row := range rows {
				if err := json.NewEncoder(&out).Encode(row); err != nil {
					return nil, err
				}
			}
		default:
			return nil, fmt.Errorf("fixture: unexpected SQL %q / %q", query, body)
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(out.String())), Request: r}, nil
	})
	// These Server values provide URLs to existing helpers; no listeners start.
	f := &fakeCH{srv: &httptest.Server{URL: "http://pr96-journal.invalid"}}
	ngfw := &httptest.Server{URL: "http://pr96-ngfw.invalid"}
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": capRule(4)}), ipsConfig(ngfw), "s", "s")
	if !e.restoreKeys(context.Background(), now) {
		t.Fatal("fixture: journal restoration failed")
	}
	if len(e.resp.Active()) != 0 {
		t.Fatal("fixture: the responder must start with an empty active list")
	}
	return e
}

// A journaled successful block outlives the responder's in-memory active list.
// Cancelling a separate pending key for that IP cannot prove that block removed.
func TestPR96UnblockRestoredDoneAndPendingNeedsManualRelease(t *testing.T) {
	for _, tc := range []struct {
		name, pendingStep string
		blocked           bool
		manual, unsaved   bool
	}{
		{name: "pending_only", pendingStep: stepFailed},
		{name: "restored_only", blocked: true},
		{name: "unsaved_only", manual: true, unsaved: true},
		{name: "saved_manual_only", manual: true},
		{name: "restored_and_unsaved", blocked: true, manual: true, unsaved: true},
		{name: "restored_and_failed", blocked: true, pendingStep: stepFailed},
		{name: "restored_and_excluded", blocked: true, pendingStep: stepExcluded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			const ip = "203.0.113.7"
			var rows []store.ResponseRow
			if tc.pendingStep != "" {
				rows = append(rows, keyRow(now.Add(-2*time.Minute).Format("2006-01-02 15:04:05"), respond.ModeIPS,
					respKey{incident: "INC-961", ip: ip, ruleID: "t-waf"}, tc.pendingStep, respond.Result{Executor: "argus"}))
			}
			if tc.blocked {
				rows = append(rows, keyRow(now.Add(-time.Minute).Format("2006-01-02 15:04:05"), respond.ModeIPS,
					respKey{incident: "INC-962", ip: ip, ruleID: "t-waf"}, stepBlocked, respond.Result{Executor: "ngfw.test", OK: true}))
			}
			if tc.manual {
				step := stepManual
				if tc.unsaved {
					step = stepBlocked // the later manual decision is absent from the journal
				}
				rows = append(rows, keyRow(now.Add(-time.Minute).Format("2006-01-02 15:04:05"), respond.ModeIPS,
					respKey{incident: "INC-963", ip: ip, ruleID: "t-waf"}, step, respond.Result{Executor: "argus", OK: true}))
			}
			e := pr96RestoredEngine(t, rows, now)
			if tc.unsaved {
				// The late pass has already cancelled this key in memory, but its
				// INSERT failed. This is the marker the next request must repair.
				e.applyKeys([]string{keyOf("INC-963", ip)}, now, false)
			}
			if tc.blocked && keyState(e, "INC-962", ip) != keyDone {
				t.Fatal("fixture: the successful block must restore as done")
			}
			if tc.pendingStep != "" && keyState(e, "INC-961", ip) != tc.pendingStep {
				t.Fatal("fixture: the independent pending key must survive restart")
			}
			code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
				`{"ip":"203.0.113.7","user":"qa","reason":"release false positive"}`)
			for _, row := range rows {
				if keyState(e, row.IncidentID, ip) != keyManual {
					t.Errorf("automatic response for %s was not cancelled", row.IncidentID)
				}
			}
			if e.unsavedKeys(ip) != 0 {
				t.Error("the successful journal write did not settle the unsaved decision")
			}
			if tc.blocked {
				if code != http.StatusUnprocessableEntity || !strings.Contains(body, "NGFW") {
					t.Fatalf("pending key hid the restored block: expected HTTP 422 with manual-release guidance, got HTTP %d %s", code, body)
				}
			} else {
				want := http.StatusUnprocessableEntity
				if tc.pendingStep != "" || tc.unsaved {
					want = http.StatusOK
				}
				if code != want {
					t.Fatalf("pending/unsaved control: expected HTTP %d, got HTTP %d %s", want, code, body)
				}
			}
		})
	}
}
