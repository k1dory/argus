package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Characterization of the policy explicitly introduced by PR75, not a failing
// regression: unblocking one false positive suppresses an independent critical
// incident from another rule for the same IP, until the global retention ends.
// This makes the security tradeoff reviewable separately from implementation
// defects and checks max(48h, block_cap_window) in memory and after a restart.
func TestPR75ManualDecisionScopeAndRetention(t *testing.T) {
	for _, tc := range []struct {
		window string
		keep   time.Duration
	}{
		{"1h", 48 * time.Hour},
		{"72h", 72 * time.Hour},
	} {
		for _, restart := range []bool{false, true} {
			name := tc.window + "/same_process"
			if restart {
				name = tc.window + "/after_restart"
			}
			t.Run(name, func(t *testing.T) {
				f := newFakeCH(t)
				x := newKeyExecutor(t)
				x.available.Store(true)
				otherRule := strings.Replace(capRule(4), "id: t-waf", "id: t-other", 1)
				otherRule = strings.Replace(otherRule, "block_cap_window: 1h", "block_cap_window: "+tc.window, 1)
				dir := rulesDirWith(t, map[string]string{"original.yml": capRule(4), "other.yml": otherRule})
				fresh := func() *engine { return testEngine(t, f, dir, ipsConfig(x.srv), "s", "s") }
				e := fresh()
				ctx := context.Background()
				e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, time.Now())
				if x.blocks.Load() != 1 || len(e.resp.Active()) != 1 {
					t.Fatal("fixture: the initial incident must block")
				}
				code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
					`{"ip":"203.0.113.7","user":"qa","reason":"INC-1 was a false positive"}`)
				if code != http.StatusOK || len(e.resp.Active()) != 0 {
					t.Fatalf("fixture: unblock must succeed: HTTP %d %s", code, body)
				}
				at, manual := e.manualAt("203.0.113.7")
				if !manual || e.respRetention() != tc.keep {
					t.Fatalf("expected IP-wide manual decision retained for %s", tc.keep)
				}
				if restart {
					saveJournal(f)
					e = fresh()
				}
				beforeExpiry := at.Add(tc.keep - time.Minute)
				e.pruneRespState(beforeExpiry, respStateTTL)
				independent := capInc("INC-2", "203.0.113.7")
				independent.RuleID = "t-other"
				e.autoRespond(ctx, []*incidents.Incident{independent}, beforeExpiry)
				if x.blocks.Load() != 1 || len(e.resp.Active()) != 0 || keyState(e, "INC-2", "203.0.113.7") != keyManual {
					t.Fatal("PR75 policy changed: the independent rule was not suppressed for the entire retention period")
				}
				afterExpiry := at.Add(tc.keep + time.Minute)
				e.pruneRespState(afterExpiry, respStateTTL)
				if _, manual := e.manualAt("203.0.113.7"); manual {
					t.Fatal("manual decision survived pruning beyond its retention period")
				}
				later := capInc("INC-3", "203.0.113.7")
				later.RuleID = "t-other"
				e.autoRespond(ctx, []*incidents.Incident{later}, afterExpiry)
				if x.blocks.Load() != 2 || len(e.resp.Active()) != 1 {
					t.Fatal("protection did not resume after the IP-wide decision expired")
				}
			})
		}
	}
}
