package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// A delayed cycle can update an already-excluded incident, not just create a
// new one. Every exclusion check, including the done-incident guard, must treat
// a committed revoke as a tombstone even when cycleAt predates its timestamp.
func TestRound3PR75RevokeResumesExistingKeyInDelayedCycle(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "live"
		if restart {
			name = "restored"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			e := keyEngine(t, f, x, 4)
			ctx, now := context.Background(), time.Now().UTC().Truncate(time.Second)
			first, cycleAt := now.Add(-time.Minute), now.Add(-5*time.Second)
			grant := exclusion{at: first.Add(-time.Minute), until: now.Add(time.Hour)}
			e.setExclusion("203.0.113.7", grant)
			if err := e.ch.InsertResponses(ctx, []store.ResponseRow{
				excludeRow("203.0.113.7", "qa", "scanner window", grant.at, grant.until),
			}); err != nil {
				t.Fatal(err)
			}
			inc := capInc("INC-75302", "203.0.113.7")
			inc.Events[0] = wafEvent(model.FormatTS(first), "203.0.113.7", "file", "")
			e.autoRespond(ctx, snapshotIncidents([]*incidents.Incident{inc}), first)
			if keyState(e, inc.IncidentID, "203.0.113.7") != keyExcluded || e.respStatus(inc.IncidentID) != "done" || x.blocks.Load() != 0 {
				t.Fatal("fixture: the existing incident must have an excluded key")
			}
			if restart {
				saveJournal(f)
				e = keyEngine(t, f, x, 4)
				e.restoreRespState([]incidents.Incident{*inc}, cycleAt.Add(-time.Second))
				if !e.restoreKeys(ctx, cycleAt.Add(-time.Second)) {
					t.Fatal("fixture: restore failed")
				}
			}

			// The cycle has fresh evidence, but is still writing/enriching its
			// incident while the operator revokes the exclusion via HTTP.
			inc.Events = append(inc.Events, wafEvent(model.FormatTS(cycleAt), "203.0.113.7", "file", ""))
			inc.EventCount = uint32(len(inc.Events))
			code, body := do(t, e.handler(), http.MethodPost, "/respond/exclude/revoke", "s",
				`{"ip":"203.0.113.7","user":"qa","reason":"scanner no longer trusted"}`)
			if code != http.StatusOK {
				t.Fatalf("fixture: revoke failed: HTTP %d %s", code, body)
			}
			if _, excluded := e.excludedUntil("203.0.113.7", cycleAt); excluded || len(e.exclusions(cycleAt)) != 0 {
				t.Fatal("fixture: the revoke must be inactive even at the delayed cycle timestamp")
			}
			e.autoRespond(ctx, snapshotIncidents([]*incidents.Incident{inc}), cycleAt)
			e.expireBlocks(ctx, time.Now().Add(2*time.Minute))
			if x.blocks.Load() != 1 {
				t.Fatalf("the done-incident guard still treated the revoke as an exclusion: blocks=%d, key=%q, eligible=%v",
					x.blocks.Load(), keyState(e, inc.IncidentID, "203.0.113.7"), e.hasExcludedKeys(inc.IncidentID, cycleAt))
			}
		})
	}
}
