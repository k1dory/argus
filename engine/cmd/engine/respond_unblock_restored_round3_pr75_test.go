package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// A journaled done key is not evidence that an unblock already succeeded.
// Restart loses Responder.active while the firewall still holds its block.
// The durability-repair success path must not claim that this block was removed.
func TestRound3PR75UnblockRestoredBlockMustNotReportFalseSuccess(t *testing.T) {
	f := newFakeCH(t)
	var blocked atomic.Bool
	var releases atomic.Int32
	firewall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/block":
			blocked.Store(true)
		case "/unblock":
			releases.Add(1)
			blocked.Store(false)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(firewall.Close)
	dir := rulesDirWith(t, map[string]string{"r.yml": capRule(4)})
	fresh := func() *engine { return testEngine(t, f, dir, ipsConfig(firewall), "s", "s") }
	e := fresh()
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-75301", "203.0.113.7")}, now)
	if !blocked.Load() || len(e.resp.Active()) != 1 || keyState(e, "INC-75301", "203.0.113.7") != keyDone {
		t.Fatal("fixture: the firewall must have an active journaled block")
	}

	saveJournal(f)
	restarted := fresh()
	if !restarted.restoreKeys(ctx, now) || keyState(restarted, "INC-75301", "203.0.113.7") != keyDone {
		t.Fatal("fixture: the blocked key must survive restart")
	}
	if len(restarted.resp.Active()) != 0 || !blocked.Load() {
		t.Fatal("fixture: only the responder's in-memory active list was lost")
	}
	code, body := do(t, restarted.handler(), http.MethodPost, "/respond/unblock", "s",
		`{"ip":"203.0.113.7","user":"qa","reason":"release confirmed false positive"}`)
	if code != http.StatusUnprocessableEntity && code != http.StatusOK {
		t.Fatalf("unexpected unblock response: HTTP %d %s", code, body)
	}
	if code == http.StatusOK && blocked.Load() {
		t.Fatalf("unblock reported success while the firewall still blocks the address: releases=%d, HTTP %d %s",
			releases.Load(), code, body)
	}
}
