package dataset

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func TestPR64CapMustNotSelectOnlyHoldout(t *testing.T) {
	// A busy rule has many independent cases on both sides of the split.
	// Derive groups and splits through Build, as dataset export does.
	var recs []*Record
	before := map[string]int{}
	for i := 0; i < 2000; i++ {
		r := Build(store.LabeledIncident{
			Incident: incidents.Incident{IncidentID: fmt.Sprintf("INC-%d", i+1), RuleID: "scan",
				ActorName: fmt.Sprintf("198.%d.%d.1", i/256, i%256)},
			Label: store.ClosureLabel{Disposition: "benign_authorized", LabeledByHuman: true},
		}, "prod")
		if r == nil {
			t.Fatal("human-labeled fixture was discarded")
		}
		recs = append(recs, r)
		before[r.Split]++
	}
	if before["train"] <= MaxPerRule || before["holdout"] <= MaxPerRule {
		t.Fatalf("fixture must have more than %d groups in each split: %v", MaxPerRule, before)
	}
	out := Cap(recs, MaxPerRule)
	if len(out) != MaxPerRule {
		t.Fatalf("cap: got %d records, want %d", len(out), MaxPerRule)
	}
	after := map[string]int{}
	for _, r := range out {
		after[r.Split]++
	}
	if after["train"] == 0 || after["holdout"] == 0 {
		t.Errorf("cap must sample independently of split, not empty one side: before=%v after=%v", before, after)
	}
	// Input order must not control which incidents survive the cap.
	for i, j := 0, len(recs)-1; i < j; i, j = i+1, j-1 {
		recs[i], recs[j] = recs[j], recs[i]
	}
	again := Cap(recs, MaxPerRule)
	if len(again) != len(out) {
		t.Fatalf("reversing input changed capped length: %d -> %d", len(out), len(again))
	}
	for i := range out {
		if out[i].IncidentID != again[i].IncidentID {
			t.Fatal("selection must stay deterministic when input is reversed")
		}
	}
}
