package eval

import (
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// The original memory test only keeps distinct above its threshold. Here the
// same 40k-event budget repeatedly crosses it: one rare port expires, a common
// port arrives below threshold, then the rare port returns. Most of the window
// is shared evidence and must not be copied for every new detection.
func TestPR113DistinctRearmingStaysWithinMemoryBudget(t *testing.T) {
	if strconv.IntSize != 64 {
		t.Skip("64 MiB allocation budget is calibrated for the deployed 64-bit engine")
	}
	const (
		total = 40000
		rare  = 300
	)
	start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	events := make([]*model.Event, 0, total)
	add := func(offset time.Duration, port uint16) {
		events = append(events, &model.Event{
			TS:     model.FormatTS(start.Add(offset)),
			Source: "netflow", SourceClass: "netflow", Action: "flow",
			SrcIP: "198.51.100.40", DstIP: "192.0.2.10", DstPort: port,
			Attrs: map[string]string{"scope": "inbound", "syn_only": "1"},
		})
	}
	for i := 0; i < rare; i++ {
		add(time.Duration(i)*time.Second, uint16(i+2))
	}
	// All common-port events remain in the window until after the last rearm.
	for i := 0; i < total-3*rare; i++ {
		add(5*time.Minute, 1)
	}
	for i := 0; i < rare; i++ {
		expires := 10*time.Minute + time.Duration(i)*time.Second
		add(expires+100*time.Millisecond, 1)
		add(expires+200*time.Millisecond, uint16(i+2))
	}
	if len(events) != total {
		t.Fatalf("fixture has %d events, want %d", len(events), total)
	}
	r := scannerRule(t, "dst.port", rare+1)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	dets, _ := Evaluate(Input{Rules: []*rules.Rule{r}, Events: events})
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	allocs := after.Mallocs - before.Mallocs
	// Suppressing legitimate rearmed detections is not an acceptable memory fix.
	if len(dets) != rare+1 {
		t.Fatalf("got %d detections, want %d genuine threshold crossings", len(dets), rare+1)
	}
	runtime.KeepAlive(dets)
	t.Logf("40k events, %d detections: %d bytes, %d allocs", len(dets), allocated, allocs)
	if allocated > 64<<20 {
		t.Errorf("distinct rearming allocated %d bytes, exceeds 64 MiB", allocated)
	}
	if allocs > 200000 {
		t.Errorf("distinct rearming made %d allocations, exceeds 200k", allocs)
	}
}
