package main

import (
	"context"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

// The exclusion may last 720h, while ordinary keys last 48h. After restart,
// restoreRespState gives done a fresh timestamp, but the excluded key keeps its
// old timestamp. Pruning must not lose the only marker that permits fresh
// events of this open incident to block after the exclusion ends.
func TestReviewPR75ExcludeExpiryAfterRestartAndKeyPruning(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "same_process"
		if restart {
			name = "after_restart"
		}
		t.Run(name, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			e := keyEngine(t, f, x, 4) // Default 1h cap window, hence 48h retention.
			ctx := context.Background()
			now := time.Now().UTC().Truncate(time.Second)
			until := now.Add(30 * time.Minute)
			at := until.Add(-excludeMaxTTL)
			first := now.Add(-respStateTTL + time.Minute)
			if err := e.ch.InsertResponses(ctx, []store.ResponseRow{
				excludeRow("203.0.113.7", "qa", "approved long scanner window", at, until),
			}); err != nil {
				t.Fatal(err)
			}
			e.setExclusion("203.0.113.7", exclusion{at: at, until: until})
			event := wafEvent(model.FormatTS(first), "203.0.113.7", "file", "")
			created, _, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{event}), first)
			if len(created) != 1 {
				t.Fatalf("fixture: created %d incidents", len(created))
			}
			id := created[0].IncidentID
			e.autoRespond(ctx, snapshotIncidents(created), first)
			if keyState(e, id, "203.0.113.7") != keyExcluded || x.blocks.Load() != 0 {
				t.Fatal("fixture: the incident must initially be deferred by the exclusion")
			}
			if restart {
				open := []incidents.Incident{*created[0]}
				saveJournal(f) // Both rows are inside their respective 30d/48h SELECT windows.
				e = keyEngine(t, f, x, 4)
				e.reg = incidents.NewRegistry(1, open)
				e.restoreRespState(open, now)
				if !e.restoreKeys(ctx, now) || keyState(e, id, "203.0.113.7") != keyExcluded {
					t.Fatal("fixture: excluded key was not restored")
				}
			}
			after := now.Add(time.Hour)
			e.pruneRespState(after, respStateTTL)
			fresh := wafEvent(model.FormatTS(after), "203.0.113.7", "file", "")
			created, updated, _ := e.reg.Apply(eval.Run(e.current(), []*model.Event{fresh}), after)
			if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != id {
				t.Fatal("fixture: fresh evidence must update the same open incident")
			}
			e.autoRespond(ctx, snapshotIncidents(updated), after)
			if x.blocks.Load() != 1 {
				t.Fatalf("expired exclusion still suppresses fresh evidence after pruning: incident=%q, key=%q, blocks=%d",
					e.respStatus(id), keyState(e, id, "203.0.113.7"), x.blocks.Load())
			}
		})
	}
}
