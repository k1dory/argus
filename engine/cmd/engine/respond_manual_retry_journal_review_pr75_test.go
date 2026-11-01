package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// A warning explicitly tells the operator to repeat the manual block once the
// journal recovers. That successful retry must persist the already applied
// manual keys, not skip them and silently leave an old automatic retry on disk.
func TestReviewPR75RetryManualBlockPersistsPreviouslyUnsavedDecision(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	if keyState(e, "INC-1", "203.0.113.7") != keyFailed {
		t.Fatal("fixture: an automatic retry must already be durable")
	}
	x.available.Store(true)
	setFail(f, "response_log", true)
	body := `{"action":"block_ip","ip":"203.0.113.7","user":"qa","reason":"reviewed manually"}`
	code, out := do(t, e.handler(), http.MethodPost, "/incidents/INC-1/respond", "s", body)
	var first struct{ Warning string }
	if err := json.Unmarshal([]byte(out), &first); err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK || first.Warning == "" || !e.keyManual(keyOf("INC-1", "203.0.113.7")) {
		t.Fatalf("fixture: expected an applied manual decision with a durability warning: HTTP %d %s", code, out)
	}
	setFail(f, "response_log", false)
	code, out = do(t, e.handler(), http.MethodPost, "/incidents/INC-1/respond", "s", body)
	var retry struct{ Warning string }
	if err := json.Unmarshal([]byte(out), &retry); err != nil {
		t.Fatal(err)
	}
	if code != http.StatusOK || retry.Warning != "" {
		t.Fatalf("fixture: retry after journal recovery should succeed without a warning: HTTP %d %s", code, out)
	}
	saveJournal(f)
	restarted := keyEngine(t, f, x, 4)
	before := x.calls.Load()
	restarted.expireBlocks(ctx, now.Add(2*time.Minute))
	if state := keyState(restarted, "INC-1", "203.0.113.7"); state != keyManual || x.calls.Load() != before {
		t.Fatalf("successful retry did not persist the decision: restored key=%q, executor calls=%d -> %d, manual rows=%d",
			state, before, x.calls.Load(), countSteps(f, stepManual))
	}
}
