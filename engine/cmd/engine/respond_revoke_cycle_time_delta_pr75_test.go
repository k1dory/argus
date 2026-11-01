package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// cycle captures now before writing incidents/enriching them and passes that
// timestamp to autoRespond later. A revoke committed during that work is a
// tombstone, not an exclusion lasting until the time of the revoke.
func TestDeltaPR75RevokeTombstoneDoesNotSuppressDelayedCycle(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	cycleAt := time.Now().UTC().Truncate(time.Second).Add(-5 * time.Second)
	inc := capInc("INC-754", "203.0.113.7")
	inc.Events[0] = wafEvent(model.FormatTS(cycleAt), "203.0.113.7", "file", "")
	for _, request := range []struct{ path, body string }{
		{"/respond/exclude", `{"ip":"203.0.113.7","ttl":"24h","user":"qa","reason":"scanner window"}`},
		{"/respond/exclude/revoke", `{"ip":"203.0.113.7","user":"qa","reason":"scanner no longer trusted"}`},
	} {
		if code, body := do(t, e.handler(), http.MethodPost, request.path, "s", request.body); code != http.StatusOK {
			t.Fatalf("fixture: %s: HTTP %d %s", request.path, code, body)
		}
	}
	if _, excluded := e.excludedUntil("203.0.113.7", time.Now()); excluded {
		t.Fatal("fixture: revocation must have taken effect")
	}
	ctx := context.Background()
	e.autoRespond(ctx, []*incidents.Incident{inc}, cycleAt)
	// No later event is required for a normal first attempt; the retry loop must
	// not strand this attempt as excluded after the exclusion was revoked.
	e.expireBlocks(ctx, time.Now().Add(2*time.Minute))
	if x.blocks.Load() != 1 {
		t.Fatalf("revocation tombstone suppressed the delayed cycle and its retries: blocks=%d, key=%q",
			x.blocks.Load(), keyState(e, inc.IncidentID, "203.0.113.7"))
	}
}
