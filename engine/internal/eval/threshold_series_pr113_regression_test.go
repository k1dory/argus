package eval

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// A new event can restore the threshold after it has already expired. Checking
// holds only after adding that event loses the intervening end of the series.
func TestPR113ThresholdRearmsAfterQuietGap(t *testing.T) {
	for _, tc := range []struct {
		name, threshold string
		seconds         []int
		ports           []uint16
		secondFirst     int
	}{
		{
			name: "count_one_empty_window", threshold: "kind: count, count: 1",
			seconds: []int{0, 120}, ports: []uint16{443, 443}, secondFirst: 1,
		},
		{
			name: "distinct_one_empty_window", threshold: "kind: distinct, field: dst.port, distinct: 1",
			seconds: []int{0, 120}, ports: []uint16{443, 443}, secondFirst: 1,
		},
		{
			name: "count_restored_by_arrival", threshold: "kind: count, count: 2",
			seconds: []int{0, 30, 75}, ports: []uint16{443, 443, 443}, secondFirst: 1,
		},
		{
			name: "distinct_restored_by_arrival", threshold: "kind: distinct, field: dst.port, distinct: 2",
			seconds: []int{0, 30, 75}, ports: []uint16{80, 443, 80}, secondFirst: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mkRule(t, fmt.Sprintf(`
title: threshold series regression
id: pr113-series
level: high
detection:
  selection: {action: fixture.hit}
  threshold: {%s, window: 1m, group_by: node}
  condition: selection and threshold
`, tc.threshold))
			start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			events := make([]*model.Event, len(tc.seconds))
			for i, sec := range tc.seconds {
				events[i] = &model.Event{
					TS:     model.FormatTS(start.Add(time.Duration(sec) * time.Second)),
					Action: "fixture.hit", Node: "fixture-node", DstPort: tc.ports[i],
				}
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != 2 {
				t.Fatalf("threshold expired during the gap: got %d detections, want two separate series", len(dets))
			}
			if !dets[1].First.Equal(events[tc.secondFirst].Time()) {
				t.Fatalf("new series starts at %s, want %s", dets[1].First, events[tc.secondFirst].Time())
			}
			if !dets[0].Last.Equal(events[len(events)-2].Time()) {
				t.Fatalf("old series extended across the gap: last=%s", dets[0].Last)
			}
		})
	}
}

// Rearming must not undo the OOM fix: expiration of some events is harmless
// when the remaining events still hold the threshold, even before the arrival.
func TestPR113ThresholdKeepsContinuouslySupportedSeries(t *testing.T) {
	r := mkRule(t, `
title: continuous series control
id: pr113-continuous
level: high
detection:
  selection: {action: fixture.hit}
  threshold: {kind: count, count: 2, window: 1m, group_by: node}
  condition: selection and threshold
`)
	start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	var events []*model.Event
	for sec := 0; sec <= 180; sec += 10 {
		events = append(events, &model.Event{
			TS:     model.FormatTS(start.Add(time.Duration(sec) * time.Second)),
			Action: "fixture.hit", Node: "fixture-node",
		})
	}
	dets := Run([]*rules.Rule{r}, events)
	if len(dets) != 1 || len(dets[0].Events) != len(events) || !dets[0].Last.Equal(events[len(events)-1].Time()) {
		t.Fatalf("continuous threshold must retain one complete detection: %+v", dets)
	}
}
