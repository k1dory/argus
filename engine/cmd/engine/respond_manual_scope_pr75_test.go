package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Policy after the PR75 review: unblocking one false positive cancels only the
// keys of that address that exist at the decision; an independent incident of
// another rule for the same IP is blocked as usual, in this process and after a
// restart. Exempting the address as a whole is the explicit /respond/exclude.
func TestPR75ManualDecisionScopeAndRetention(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "same_process"
		if restart {
			name = "after_restart"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			otherRule := strings.Replace(capRule(4), "id: t-waf", "id: t-other", 1)
			dir := rulesDirWith(t, map[string]string{"original.yml": capRule(4), "other.yml": otherRule})
			fresh := func() *engine { return testEngine(t, f, dir, ipsConfig(x.srv), "s", "s") }
			e := fresh()
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
			if x.blocks.Load() != 1 || len(e.resp.Active()) != 1 {
				t.Fatal("fixture: the initial incident must block")
			}
			code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
				`{"ip":"203.0.113.7","user":"qa","reason":"INC-1 was a false positive"}`)
			if code != http.StatusOK || len(e.resp.Active()) != 0 || keyState(e, "INC-1", "203.0.113.7") != keyManual {
				t.Fatalf("fixture: unblock must succeed and cancel INC-1: HTTP %d %s", code, body)
			}
			if _, excluded := e.excludedUntil("203.0.113.7", now); excluded {
				t.Fatal("an unblock must not exempt the address")
			}
			if restart {
				saveJournal(f)
				e = fresh()
				e.restoreRespState([]incidents.Incident{*capInc("INC-1", "203.0.113.7")}, now)
			}
			// The same incident stays cancelled: its new events do not re-block.
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now.Add(time.Minute))
			if x.blocks.Load() != 1 {
				t.Fatal("the cancelled incident re-blocked the address")
			}
			independent := capInc("INC-2", "203.0.113.7")
			independent.RuleID = "t-other"
			e.autoRespond(ctx, []*incidents.Incident{independent}, now.Add(2*time.Minute))
			if x.blocks.Load() != 2 || len(e.resp.Active()) != 1 || keyState(e, "INC-2", "203.0.113.7") != keyDone {
				t.Fatalf("an unblock of INC-1 suppressed an independent incident: blocks=%d state=%q", x.blocks.Load(), keyState(e, "INC-2", "203.0.113.7"))
			}
		})
	}
}
