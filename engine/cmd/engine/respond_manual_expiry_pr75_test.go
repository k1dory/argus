package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// A new incident first seen just before an IP-wide override expires must not
// retain that exemption for another respStateTTL. After the override expires,
// fresh trusted evidence for the same open incident must reach the responder.
func TestPR75ManualExpiryReconsidersSuppressedIncident(t *testing.T) {
	for _, window := range []string{"1h", "72h"} {
		t.Run(window, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			rule := strings.Replace(capRule(4), "block_cap_window: 1h", "block_cap_window: "+window, 1)
			e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": rule}), ipsConfig(x.srv), "s", "s")
			ctx := context.Background()
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, time.Now())
			if x.blocks.Load() != 1 {
				t.Fatal("fixture: the original incident must block")
			}
			code, body := do(t, e.handler(), http.MethodPost, "/respond/unblock", "s",
				`{"ip":"203.0.113.7","user":"qa","reason":"INC-1 was a false positive"}`)
			if code != http.StatusOK || len(e.resp.Active()) != 0 {
				t.Fatalf("fixture: manual unblock: HTTP %d %s", code, body)
			}
			at, manual := e.manualAt("203.0.113.7")
			if !manual {
				t.Fatal("fixture: expected the address-wide decision")
			}
			beforeExpiry := at.Add(e.respRetention() - time.Minute)
			e.pruneRespState(beforeExpiry, respStateTTL)
			inc := capInc("INC-2", "203.0.113.7")
			inc.Events[0] = wafEvent(model.FormatTS(beforeExpiry), "203.0.113.7", "file", "")
			e.autoRespond(ctx, []*incidents.Incident{inc}, beforeExpiry)
			if x.blocks.Load() != 1 || keyState(e, "INC-2", "203.0.113.7") != keyManual {
				t.Fatal("fixture: the new incident must be suppressed while the decision is still valid")
			}

			afterExpiry := at.Add(e.respRetention() + time.Minute)
			e.pruneRespState(afterExpiry, respStateTTL)
			if _, manual := e.manualAt("203.0.113.7"); manual {
				t.Fatal("fixture: the IP-wide override must have expired")
			}
			// This is an update within the rule's 30m dedupe window, not a new
			// incident ID: the ordinary engine cycle passes it to autoRespond.
			inc.Events = append(inc.Events, wafEvent(model.FormatTS(afterExpiry), "203.0.113.7", "file", ""))
			inc.EventCount = uint32(len(inc.Events))
			e.autoRespond(ctx, []*incidents.Incident{inc}, afterExpiry)
			if x.blocks.Load() != 2 || len(e.resp.Active()) != 1 {
				t.Fatalf("expired manual decision still suppresses fresh evidence for the same incident: incident state=%q, key=%q, blocks=%d",
					e.respStatus("INC-2"), keyState(e, "INC-2", "203.0.113.7"), x.blocks.Load())
			}
		})
	}
}
