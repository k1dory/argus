package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// This test uses helpers and APIs present on main as well as in PR #67.
// The journal remains available throughout. Both cancelling a pending block
// and successfully blocking/unblocking manually must cancel its old retry.
func TestPR67ManualUnblockCancelsAutomaticRetry(t *testing.T) {
	for _, manualBlock := range []bool{false, true} {
		name := "pending_only"
		if manualBlock {
			name = "manual_block_then_unblock"
		}
		t.Run(name, func(t *testing.T) {
			var available atomic.Bool
			var calls, blocks atomic.Int32
			x := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/block" {
					return
				}
				calls.Add(1)
				if !available.Load() {
					http.Error(w, "fixture executor unavailable", http.StatusServiceUnavailable)
					return
				}
				blocks.Add(1)
			}))
			t.Cleanup(x.Close)
			f := newFakeCH(t)
			e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": respondRule}), ipsConfig(x), "s", "s")
			ctx, now := context.Background(), time.Now()
			inc := &incidents.Incident{
				IncidentID: "INC-1", RuleID: "t-waf", RuleTitle: "WAF RCE", Level: "critical", EventCount: 2,
				Events: []*model.Event{
					wafEvent(model.FormatTS(now.Add(-time.Second)), "203.0.113.7", "file", ""),
					wafEvent(model.FormatTS(now), "203.0.113.7", "file", ""),
				},
			}
			e.autoRespond(ctx, []*incidents.Incident{inc}, now)
			if calls.Load() != 1 || blocks.Load() != 0 {
				t.Fatal("fixture: initial automatic attempt must fail")
			}
			available.Store(true)
			h := e.handler()
			if manualBlock {
				code, body := do(t, h, "POST", "/incidents/INC-1/respond", "s",
					`{"action":"block_ip","ip":"203.0.113.7","user":"qa","reason":"manual review"}`)
				if code != http.StatusOK || blocks.Load() != 1 {
					t.Fatalf("fixture: manual block failed: %d %s", code, body)
				}
			}
			code, body := do(t, h, "POST", "/respond/unblock", "s",
				`{"ip":"203.0.113.7","user":"qa","reason":"false positive, cancel blocking"}`)
			if code != http.StatusOK {
				t.Errorf("operator must be able to cancel the pending block: HTTP %d %s", code, body)
			}
			callsBefore, blocksBefore := calls.Load(), blocks.Load()
			e.expireBlocks(ctx, now.Add(61*time.Second))
			if calls.Load() != callsBefore || blocks.Load() != blocksBefore || len(e.resp.Active()) != 0 {
				t.Fatalf("automatic retry overrode manual cancellation: calls %d -> %d, blocks %d -> %d, active=%v",
					callsBefore, calls.Load(), blocksBefore, blocks.Load(), e.resp.Active())
			}
		})
	}
}
