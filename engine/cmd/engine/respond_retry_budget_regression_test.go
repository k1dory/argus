package main

import (
	"context"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// Failed attempts are durable; restarting before the last retry must not
// replenish the per-key budget of one initial attempt plus three retries.
func TestPR67RestartPreservesRetryBudget(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t) // every executor call fails
	e := keyEngine(t, f, x, 1)
	ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	e.expireBlocks(ctx, t0.Add(time.Minute+time.Second))
	e.expireBlocks(ctx, t0.Add(6*time.Minute+2*time.Second))
	if got := x.calls.Load(); got != 3 {
		t.Fatalf("fixture: three attempts before restart, got %d", got)
	}
	saveJournal(f)
	restarted := keyEngine(t, f, x, 1)
	restarted.expireBlocks(ctx, t0.Add(22*time.Minute))
	if state := keyState(restarted, "INC-1", "203.0.113.7"); state != keyExhausted {
		t.Errorf("fourth total failure must exhaust the key, got %q", state)
	}
	restarted.expireBlocks(ctx, t0.Add(28*time.Minute))
	if got := x.calls.Load(); got != int32(respond.MaxAttempts) {
		t.Fatalf("restart replenished the retry budget: %d calls, maximum %d", got, respond.MaxAttempts)
	}
}
