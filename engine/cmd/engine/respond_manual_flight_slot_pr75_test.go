package main

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// The first flight owns a cap slot but has no respKeys entry yet. Cancelling
// that flight must release its slot even when the executor finishes afterwards.
// Otherwise the next attacker in the same /24 incorrectly hits block_cap.
func TestPR75ManualCancelFirstFlightReleasesCapSlot(t *testing.T) {
	for _, executorSucceeds := range []bool{false, true} {
		name := "executor_fails"
		if executorSucceeds {
			name = "executor_succeeds_then_unblocks"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(executorSucceeds)
			x.gate, x.entered = make(chan struct{}), make(chan struct{}, 1)
			var once sync.Once
			release := func() { once.Do(func() { close(x.gate) }) }
			t.Cleanup(release)
			e := keyEngine(t, f, x, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			now := time.Now().UTC().Truncate(time.Second)
			attemptDone := make(chan struct{})
			go func() {
				defer close(attemptDone)
				e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
			}()
			select {
			case <-x.entered:
			case <-ctx.Done():
				t.Fatal("first attempt did not reach the executor")
			}
			if e.keySnapshot(keyOf("INC-1", "203.0.113.7")) != nil {
				t.Fatal("fixture: the first flight must not have stored its key yet")
			}
			type reply struct {
				code int
				body string
			}
			manualDone := make(chan reply, 1)
			go func() {
				code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
					`{"ip":"203.0.113.7","user":"qa","reason":"cancel this false positive"}`)
				manualDone <- reply{code, body}
			}()
			// Wait for the actual decision, not for an assumed scheduler delay.
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				if e.keyManual(keyOf("INC-1", "203.0.113.7")) {
					break
				}
				select {
				case <-tick.C:
				case <-ctx.Done():
					t.Fatal("manual decision did not reach the in-flight address")
				}
			}
			release()
			select {
			case <-attemptDone:
			case <-ctx.Done():
				t.Fatal("first attempt did not finish")
			}
			select {
			case res := <-manualDone:
				if res.code != http.StatusOK {
					t.Fatalf("cancellation: HTTP %d %s", res.code, res.body)
				}
			case <-ctx.Done():
				t.Fatal("manual cancellation did not finish")
			}
			if keyState(e, "INC-1", "203.0.113.7") != keyManual || len(e.resp.Active()) != 0 {
				t.Fatal("fixture: cancellation must leave a manual key and no active block")
			}
			x.available.Store(true)
			before := x.blocks.Load()
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, now.Add(time.Second))
			if x.blocks.Load() != before+1 || keyState(e, "INC-2", "203.0.113.8") != keyDone {
				t.Fatalf("cancelled first flight leaked the subnet's only cap slot: next IP state=%q, blocks=%d -> %d",
					keyState(e, "INC-2", "203.0.113.8"), before, x.blocks.Load())
			}
		})
	}
}
