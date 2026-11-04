package eval

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Controls for the retention regression: dropping obsolete storage must not
// overwrite evidence of an earlier detection when the window slides, resets,
// or grows through a reallocation. Appending in the consumer must be safe too.
func TestPR115EvidenceSurvivesGrowthAndInputCompaction(t *testing.T) {
	for _, tc := range []struct {
		name, config string
		reset        bool
	}{
		{"selection", "", false},
		{"count", "  threshold: {kind: count, count: 2, window: 1s, group_by: node}\n", false},
		{"distinct", "  threshold: {kind: distinct, field: object, distinct: 2, window: 1s, group_by: node}\n", false},
		{"consecutive", "  reset: {action: fixture.reset}\n  threshold: {kind: consecutive, count: 2, window: 1s, group_by: node}\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			condition := "selection"
			if tc.config != "" {
				condition += " and threshold"
			}
			r := mkRule(t, fmt.Sprintf(`
title: evidence aliasing control
id: pr115-evidence-aliasing
level: high
dedupe: 1s
detection:
  selection: {action: fixture.hit}
  group_by: node
%s  condition: %s
`, tc.config, condition))
			start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			var events []*model.Event
			var want [][]*model.Event
			// Large bursts force growth; the small tail bursts exercise reuse
			// of an already allocated array between separate detections.
			for burst, size := range []int{64, 64, 800, 4, 4} {
				at := start.Add(time.Duration(burst) * 2 * time.Second)
				var series []*model.Event
				for i := 0; i < size; i++ {
					ev := &model.Event{
						TS:   model.FormatTS(at.Add(time.Duration(i) * time.Millisecond)),
						Node: "fixture-node", Action: "fixture.hit", Object: fmt.Sprintf("%d/%d", burst, i),
					}
					events = append(events, ev)
					series = append(series, ev)
				}
				want = append(want, series)
				if tc.reset {
					events = append(events, &model.Event{
						TS:   model.FormatTS(at.Add(time.Duration(size) * time.Millisecond)),
						Node: "fixture-node", Action: "fixture.reset",
					})
				}
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != len(want) {
				t.Fatalf("got %d detections, want %d independent series", len(dets), len(want))
			}
			for _, det := range dets {
				// This must not overwrite any other detection's evidence.
				appended := append(det.Events, &model.Event{Object: "consumer append"})
				if len(appended) != len(det.Events)+1 {
					t.Fatal("consumer append lost an event")
				}
			}
			// The engine compacts its received-at buffer in place after an
			// evaluation. This must not modify any retained detection either.
			copy(events, events[len(events)-2:])
			clear(events[2:])
			for i, det := range dets {
				if len(det.Events) != len(want[i]) || !det.First.Equal(want[i][0].Time()) || !det.Last.Equal(want[i][len(want[i])-1].Time()) {
					t.Fatalf("series %d changed its extent: %+v", i, det)
				}
				for j, ev := range det.Events {
					if ev != want[i][j] {
						t.Fatalf("series %d evidence[%d] overwritten after growth/reset/append/compaction", i, j)
					}
				}
			}
		})
	}
}
