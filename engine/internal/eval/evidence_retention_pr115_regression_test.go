package eval

import (
	"fmt"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// A detection can outlive the input buffer: incidents.build stores Events and
// Registry.Apply keeps them even when a replay brings no new evidence. Keeping
// two events must not also keep every expired/reset event in the group alive.
func TestPR115EvidenceReleasesDiscardedPrefix(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name, kind, resetSelection := "expired", "count", ""
		if reset {
			name, kind, resetSelection = "reset", "consecutive", "  reset: {action: fixture.reset}\n"
		}
		t.Run(name, func(t *testing.T) {
			r := mkRule(t, fmt.Sprintf(`
title: evidence retention regression
id: pr115-evidence-retention
level: high
detection:
  selection: {action: fixture.hit}
%s  threshold: {kind: %s, count: 2, window: 1s, group_by: node}
  condition: selection and threshold
`, resetSelection, kind))
			dets, discarded := pr115DiscardedPrefix(r, reset)
			if len(dets) != 1 || len(dets[0].Events) != 2 {
				t.Fatalf("fixture: want exactly one two-event detection, got %+v", dets)
			}
			for _, ev := range dets[0].Events {
				if ev.Object != "current evidence" {
					t.Fatalf("fixture: discarded event is visible evidence: %+v", ev)
				}
			}
			// The helper's input slice is gone. Event is not a tiny pointer-free
			// allocation, so the runtime's tiny-object batching does not apply.
			runtime.GC()
			runtime.GC()
			retained := discarded.Value() != nil
			runtime.KeepAlive(dets)
			if retained {
				t.Fatal("two-event evidence keeps the discarded prefix alive after the input buffer is released")
			}
		})
	}
}

// Returning only detections and a weak pointer prevents a test-local strong
// reference from making the discarded event live across the GC assertion.
//
//go:noinline
func pr115DiscardedPrefix(r *rules.Rule, reset bool) ([]Detection, weak.Pointer[model.Event]) {
	start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	const oldEvents = 1024
	events := make([]*model.Event, 0, 2*oldEvents+2)
	add := func(at time.Duration, action, object string) {
		events = append(events, &model.Event{
			TS: model.FormatTS(start.Add(at)), Node: "fixture-node",
			Action: action, Object: object,
		})
	}
	for i := 0; i < oldEvents; i++ {
		at := time.Duration(i) * 2 * time.Second
		if reset {
			at = time.Duration(i) * 2 * time.Millisecond
		}
		add(at, "fixture.hit", "discarded prefix")
		if reset {
			add(at+time.Millisecond, "fixture.reset", "")
		}
	}
	discarded := weak.Make(events[0])
	last := time.Duration(oldEvents) * 2 * time.Second
	if reset {
		last = time.Duration(oldEvents) * 2 * time.Millisecond
	}
	add(last, "fixture.hit", "current evidence")
	add(last+time.Millisecond, "fixture.hit", "current evidence")
	return Run([]*rules.Rule{r}, events), discarded
}
