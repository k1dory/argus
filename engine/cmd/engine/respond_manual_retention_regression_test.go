package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// With a 72h response retention window, pruning after 49h must not erase an
// operator decision for a still-open incident. Use the real evaluator and
// registry to verify that the later event updates the same incident/key.
func TestPR67ManualDecisionSurvivesExtendedRetention(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	rule := strings.Replace(capRule(1), "block_cap_window: 1h", "block_cap_window: 72h", 1)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": rule}), ipsConfig(x.srv), "s", "s")
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	event := wafEvent(model.FormatTS(now), "203.0.113.7", "file", "")
	created, _, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{event}), now)
	if len(created) != 1 {
		t.Fatalf("fixture: expected one incident, got %d", len(created))
	}
	id := created[0].IncidentID
	e.autoRespond(ctx, snapshotIncidents(created), now)
	if keyState(e, id, "203.0.113.7") != keyFailed {
		t.Fatal("fixture: first automatic attempt must fail")
	}
	code, body := do(t, e.handler(), "POST", "/respond/unblock", "s",
		`{"ip":"203.0.113.7","user":"qa","reason":"false positive, cancel blocking"}`)
	if code != http.StatusOK || keyState(e, id, "203.0.113.7") != keyManual {
		t.Fatalf("fixture: expected a terminal manual decision: HTTP %d %s", code, body)
	}
	if countSteps(f, stepManual) != 1 || e.respRetention() != 72*time.Hour {
		t.Fatal("fixture: the manual decision is journaled within a 72h retention window")
	}

	later := now.Add(49 * time.Hour)
	e.reg.Prune(later, 24*time.Hour, nil)
	e.pruneRespState(later, respStateTTL) // same argument as the regular engine cycle
	next := wafEvent(model.FormatTS(later), "203.0.113.7", "file", "")
	created, updated, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{next}), later)
	if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != id {
		t.Fatalf("fixture: later event must update the same open incident: created=%v updated=%v", created, updated)
	}
	x.available.Store(true)
	callsBefore := x.calls.Load()
	e.autoRespond(ctx, snapshotIncidents(updated), later)
	if x.calls.Load() != callsBefore || len(e.resp.Active()) != 0 {
		t.Fatalf("pruning forgot manual before the 72h retention window ended: calls %d -> %d, state=%q, active=%v",
			callsBefore, x.calls.Load(), keyState(e, id, "203.0.113.7"), e.resp.Active())
	}
}
