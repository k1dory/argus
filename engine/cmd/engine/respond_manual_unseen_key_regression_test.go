package main

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// The first attempt has a flight and a cap slot before it has a respKeys entry.
// A second incident for the same IP can therefore be in flight while an older
// failed key makes the operator's cancellation return HTTP 200. Both keys must
// become manual, including after the in-flight executor returns a failure.
func TestPR67ManualCancelIncludesFirstFlight(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	release := make(chan struct{}, 1)
	release <- struct{}{} // Allow the older incident's first attempt to fail.
	x.gate, x.entered = release, make(chan struct{}, 2)
	var once sync.Once
	releaseAttempt := func() { once.Do(func() { close(release) }) }
	t.Cleanup(releaseAttempt)
	e := keyEngine(t, f, x, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	<-x.entered
	if keyState(e, "INC-1", "203.0.113.7") != keyFailed {
		t.Fatal("fixture: the older incident must have a failed automatic attempt")
	}

	attemptDone := make(chan struct{})
	go func() {
		defer close(attemptDone)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.7")}, now)
	}()
	select {
	case <-x.entered:
	case <-ctx.Done():
		t.Fatal("second incident did not reach its first executor call")
	}

	type response struct {
		code int
		body string
	}
	manualDone := make(chan response, 1)
	go func() {
		code, body := do(t, e.handler(), "POST", "/respond/unblock", "s",
			`{"ip":"203.0.113.7","user":"qa","reason":"false positive, cancel this address"}`)
		manualDone <- response{code, body}
	}()
	// This observable transition proves operatorOverride has run. The HTTP
	// handler is now waiting for Unblock's IP lock, held by the first flight.
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for keyState(e, "INC-1", "203.0.113.7") != keyManual {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("manual cancellation did not reach the known key")
		}
	}
	releaseAttempt()
	select {
	case <-attemptDone:
	case <-ctx.Done():
		t.Fatal("in-flight attempt did not finish")
	}
	select {
	case res := <-manualDone:
		if res.code != http.StatusOK {
			t.Fatalf("pending cancellation: HTTP %d %s", res.code, res.body)
		}
	case <-ctx.Done():
		t.Fatal("manual cancellation did not finish")
	}
	if state := keyState(e, "INC-2", "203.0.113.7"); state != keyManual {
		t.Errorf("first flight overwrote the operator's decision: state=%q, want manual", state)
	}
	x.available.Store(true)
	callsBefore := x.calls.Load()
	e.expireBlocks(ctx, now.Add(2*time.Minute))
	if x.calls.Load() != callsBefore || len(e.resp.Active()) != 0 {
		t.Fatalf("HTTP 200 cancellation was followed by an automatic block: calls %d -> %d, active=%v",
			callsBefore, x.calls.Load(), e.resp.Active())
	}
}

// serveHTTP starts before OpenIncidents/restoreKeys. A successful manual block
// and unblock during startup must cancel an older journaled retry, even though
// that retry's key has not been loaded into memory yet.
func TestPR67ManualCancelBeforeRestoreDoesNotRearmRetry(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	beforeRestart := keyEngine(t, f, x, 4)
	beforeRestart.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	if keyState(beforeRestart, "INC-1", "203.0.113.7") != keyFailed {
		t.Fatal("fixture: a failed automatic attempt must be in the journal")
	}

	e := keyEngine(t, f, x, 4)
	x.available.Store(true)
	code, body := do(t, e.handler(), "POST", "/incidents/INC-1/respond", "s",
		`{"action":"block_ip","ip":"203.0.113.7","user":"qa","reason":"manual review"}`)
	if code != http.StatusOK || x.blocks.Load() != 1 {
		t.Fatalf("fixture: manual block failed: HTTP %d %s", code, body)
	}
	code, body = do(t, e.handler(), "POST", "/respond/unblock", "s",
		`{"ip":"203.0.113.7","user":"qa","reason":"false positive, cancel blocking"}`)
	if code != http.StatusOK || len(e.resp.Active()) != 0 {
		t.Fatalf("fixture: manual unblock failed: HTTP %d %s", code, body)
	}
	// Include every persisted row, including both manual actions, in the read.
	saveJournal(f)
	callsBefore := x.calls.Load()
	e.expireBlocks(ctx, now.Add(2*time.Minute))
	if x.calls.Load() != callsBefore || len(e.resp.Active()) != 0 {
		t.Fatalf("startup restoration rearmed a manually cancelled retry: calls %d -> %d, active=%v",
			callsBefore, x.calls.Load(), e.resp.Active())
	}
}
