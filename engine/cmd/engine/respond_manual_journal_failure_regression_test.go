package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// An acknowledged cancellation must survive a restart. An INSERT failure may
// be reported to the operator, but must not be acknowledged as durable success
// while the old failed row can still restore an automatic retry.
func TestPR67AcknowledgedManualCancelSurvivesJournalFailure(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	if keyState(e, "INC-1", "203.0.113.7") != keyFailed || countSteps(f, stepFailed) == 0 {
		t.Fatal("fixture: the retry must be journaled before the outage")
	}
	setFail(f, "response_log", true)
	code, body := do(t, e.handler(), "POST", "/respond/unblock", "s",
		`{"ip":"203.0.113.7","user":"qa","reason":"false positive, cancel blocking"}`)
	setFail(f, "response_log", false)
	if code == http.StatusBadGateway || code == http.StatusServiceUnavailable {
		return // Explicit failure is acceptable; the operator can retry.
	}
	if code != http.StatusOK {
		t.Fatalf("unexpected cancellation response: HTTP %d %s", code, body)
	}
	x.available.Store(true)
	// Normal cycles after storage recovers must either persist the acknowledged
	// decision or leave an already durable manual record for the next process.
	e.expireBlocks(ctx, now.Add(30*time.Second))
	saveJournal(f)
	restarted := keyEngine(t, f, x, 4)
	callsBefore := x.calls.Load()
	restarted.expireBlocks(ctx, now.Add(2*time.Minute))
	if x.calls.Load() != callsBefore || len(restarted.resp.Active()) != 0 {
		t.Fatalf("acknowledged cancellation was lost after INSERT failure and restart: calls %d -> %d, active=%v",
			callsBefore, x.calls.Load(), restarted.resp.Active())
	}
}
