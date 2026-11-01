package incidents

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr50ReviewCollectorStallRule(t *testing.T) *rules.Rule {
	t.Helper()
	r, err := rules.LoadFile(filepath.Join("..", "..", "..", "rules", "ops", "collector-sink-stalled.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if r.ID != "a41c-ops-066" {
		t.Fatalf("unexpected rule: %q", r.ID)
	}
	return r
}

func pr50ReviewCollectorStallEvent(now time.Time, action, transport string) *model.Event {
	e := &model.Event{
		TS: model.FormatTS(now), Source: "argus.collector", SourceClass: "telemetry",
		Vendor: "ARGUS", Product: "collector", Action: action,
		ActorName: "argus-collector", ActorKind: "system", Node: "argus-collector",
		Outcome: "failure", Severity: 7, Value: 600, Unit: "seconds",
		Attrs: map[string]string{"transport": transport, "pending_rows": "1", "stalled_passes": "1"},
	}
	if action == "collector.sink_recovered" {
		e.Outcome, e.Severity, e.Value = "success", 0, 0
		e.Attrs["pending_rows"] = "0"
	}
	return e
}

// POST /ingest/events accepts source/action/node from the sender. Production
// emitHTTPBatch overwrites attrs.transport with "http", so only that origin
// marker distinguishes this payload from the collector's own direct INSERT.
// An ingest-token holder must not close the collector's operational incident.
func TestPR50ReviewCollectorStallCloseRequiresInternalOrigin(t *testing.T) {
	r := pr50ReviewCollectorStallRule(t)
	for _, transport := range []string{"internal", "http"} {
		t.Run(transport, func(t *testing.T) {
			now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
			stall := pr50ReviewCollectorStallEvent(now, "collector.sink_stalled", "internal")
			reg := NewRegistry(0, nil)
			created, _, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{stall}), now)
			if len(created) != 1 {
				t.Fatalf("fixture must open the real collector incident: created=%d", len(created))
			}
			incident := created[0]
			recovery := pr50ReviewCollectorStallEvent(now.Add(time.Minute), "collector.sink_recovered", transport)
			_, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: []*model.Event{recovery}})
			for _, closer := range closers {
				reg.Close(closer.Rule.ID, closer.Key, "fixture: recovery", closer.Event.Time(), now.Add(time.Minute))
			}
			if got, want := incident.Status == StatusClosed, transport == "internal"; got != want {
				t.Fatalf("transport=%q changed the internal incident incorrectly: status=%q wantClosed=%t", transport, incident.Status, want)
			}
		})
	}
}

// The same boundary applies to opening an incident: an external integration
// can choose the reserved source name but cannot set transport=internal.
func TestPR50ReviewCollectorStallSelectionRequiresInternalOrigin(t *testing.T) {
	r := pr50ReviewCollectorStallRule(t)
	for _, transport := range []string{"internal", "http"} {
		t.Run(transport, func(t *testing.T) {
			event := pr50ReviewCollectorStallEvent(time.Now(), "collector.sink_stalled", transport)
			dets := eval.Run([]*rules.Rule{r}, []*model.Event{event})
			want := 0
			if transport == "internal" {
				want = 1
			}
			if len(dets) != want {
				t.Fatalf("transport=%q can spoof a collector outage: detections=%d want=%d", transport, len(dets), want)
			}
		})
	}
}
