package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// The HTTP server starts before restoreKeys. A journaled exclusion is not
// absent just because restoration has not populated respExcluded yet.
func TestReviewPR75RevokeLoadsPersistedExclusionBeforeAnswering(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	now := time.Now().UTC().Truncate(time.Second)
	row := excludeRow("203.0.113.7", "qa", "scanner window", now.Add(-time.Hour), now.Add(time.Hour))
	if err := e.ch.InsertResponses(context.Background(), []store.ResponseRow{row}); err != nil {
		t.Fatal(err)
	}
	saveJournal(f)
	code, body := do(t, e.handler(), http.MethodPost, "/respond/exclude/revoke", "s",
		`{"ip":"203.0.113.7","user":"qa","reason":"window revoked"}`)
	if code != http.StatusOK {
		t.Fatalf("revoke rejected an active durable exclusion before startup restoration: HTTP %d %s", code, body)
	}
	saveJournal(f)
	restarted := keyEngine(t, f, x, 4)
	if !restarted.restoreKeys(context.Background(), now) {
		t.Fatal("journal restoration failed")
	}
	if _, excluded := restarted.excludedUntil("203.0.113.7", now); excluded {
		t.Fatal("the acknowledged revocation did not survive restart")
	}
}

// A SELECT can capture an exclusion before a local revoke commits. Replay that
// captured response after the real revoke endpoint completes. This models the
// stale-result interleaving without scheduler-dependent sleeps: saveJournal
// snapshots the read side, and subsequent INSERTs do not update that snapshot.
// Revocation needs a tombstone or synchronization with restoration.
func TestReviewPR75DelayedRestoreCannotResurrectRevokedExclusion(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	code, body := do(t, e.handler(), http.MethodPost, "/respond/exclude", "s",
		`{"ip":"203.0.113.7","ttl":"720h","user":"qa","reason":"scanner window"}`)
	if code != http.StatusOK {
		t.Fatalf("fixture: exclude: HTTP %d %s", code, body)
	}
	saveJournal(f)
	code, body = do(t, e.handler(), http.MethodPost, "/respond/exclude/revoke", "s",
		`{"ip":"203.0.113.7","user":"qa","reason":"window revoked"}`)
	if code != http.StatusOK || countSteps(f, stepExclude) != 2 {
		t.Fatalf("fixture: revoke must commit its row: HTTP %d %s", code, body)
	}
	if _, excluded := e.excludedUntil("203.0.113.7", time.Now()); excluded {
		t.Fatal("fixture: the revoke must have taken effect before replay")
	}
	ctx := context.Background()
	if !e.restoreKeys(ctx, time.Now()) {
		t.Fatal("restoration of the captured pre-revoke snapshot failed")
	}
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-75", "203.0.113.7")}, time.Now())
	if x.blocks.Load() != 1 {
		t.Fatalf("a stale SELECT resurrected a revoked exclusion: blocks=%d, key=%q, exclusions=%v",
			x.blocks.Load(), keyState(e, "INC-75", "203.0.113.7"), e.exclusions(time.Now()))
	}
}
