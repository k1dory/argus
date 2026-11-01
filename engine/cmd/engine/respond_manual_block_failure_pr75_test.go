package main

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// A request to block an address is not a request to exempt it from protection.
// If every manual executor fails, a later, independent incident must still be
// eligible for an automatic block, both in this process and after restoration.
func TestPR75FailedManualBlockDoesNotSuppressNewIncident(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "same_process"
		if restart {
			name = "after_restart"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t) // All /block calls initially return 503.
			e := keyEngine(t, f, x, 4)
			code, body := do(t, e.handler(), http.MethodPost, "/incidents/INC-1/respond", "s",
				`{"action":"block_ip","ip":"203.0.113.7","user":"qa","reason":"confirmed attack, block this address"}`)
			var result struct {
				Results []respond.Result `json:"results"`
			}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Fatalf("decode manual response: %v", err)
			}
			if code != http.StatusOK || len(result.Results) != 1 || result.Results[0].OK || x.calls.Load() != 1 || len(e.resp.Active()) != 0 {
				t.Fatalf("fixture: expected one failed manual executor and no active block: HTTP %d %s", code, body)
			}
			if restart {
				saveJournal(f)
				e = keyEngine(t, f, x, 4)
			}
			x.available.Store(true)
			e.autoRespond(context.Background(), []*incidents.Incident{capInc("INC-2", "203.0.113.7")}, time.Now())
			if x.blocks.Load() != 1 || len(e.resp.Active()) != 1 {
				t.Fatalf("failed manual block disabled protection for a new incident: calls=%d blocks=%d state=%q active=%v",
					x.calls.Load(), x.blocks.Load(), keyState(e, "INC-2", "203.0.113.7"), e.resp.Active())
			}
		})
	}
}
