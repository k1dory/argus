package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// The second pass must not cancel an independent first flight which began
// after the operator's decision and never installed the block being removed.
// Pause that flight immediately after beginFlight, a real scheduling point in
// attemptKey, while the previous incident's unblock request is at the NGFW.
func TestReviewPR75UnblockLatePassDoesNotCancelUnrelatedNewFlight(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseUnblock := func() { once.Do(func() { close(release) }) }
	unblock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(unblock.Close)
	t.Cleanup(releaseUnblock)
	cfg := ipsConfig(x.srv)
	cfg.HTTP[0].Unblock = &respond.HTTPCall{URL: unblock.URL + "/unblock", Body: `{"ip":"${ip}"}`}
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": capRule(4)}), cfg, "s", "s")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	if x.blocks.Load() != 1 {
		t.Fatal("fixture: INC-1 must have an active block")
	}
	type reply struct {
		code int
		body string
	}
	done := make(chan reply, 1)
	go func() {
		code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
			`{"ip":"203.0.113.7","user":"qa","reason":"INC-1 was a false positive"}`)
		done <- reply{code, body}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("unblock did not reach the executor")
	}
	if !e.keyManual(keyOf("INC-1", "203.0.113.7")) {
		t.Fatal("fixture: the original decision must already be durable and applied")
	}
	lateKey := keyOf("INC-2", "203.0.113.7")
	if !e.beginFlight(lateKey) {
		t.Fatal("fixture: the independent incident must have no previous flight")
	}
	t.Cleanup(func() { e.endFlight(lateKey) })
	releaseUnblock()
	select {
	case res := <-done:
		if res.code != http.StatusOK {
			t.Fatalf("unblock: HTTP %d %s", res.code, res.body)
		}
	case <-ctx.Done():
		t.Fatal("unblock did not finish")
	}
	e.endFlight(lateKey)
	// Resume the ordinary attempt for the new incident. No executor call for it
	// could have been removed by the earlier Unblock: it had not reached one.
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.7")}, now.Add(time.Second))
	if x.blocks.Load() != 2 || keyState(e, "INC-2", "203.0.113.7") == keyManual {
		t.Fatalf("late pass exempted a new incident outside the original decision: blocks=%d, key=%q",
			x.blocks.Load(), keyState(e, "INC-2", "203.0.113.7"))
	}
}
