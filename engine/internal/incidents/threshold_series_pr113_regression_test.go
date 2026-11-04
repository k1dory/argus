package incidents

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Replay of the retained buffer after auto_close must open a fresh incident
// using the new series, without importing expired evidence from the closed one.
func TestPR113AutoCloseReopenUsesOnlyTheNewThresholdSeries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rule.yml")
	if err := os.WriteFile(path, []byte(`
title: threshold reopen regression
id: pr113-reopen
level: high
detection:
  selection: {action: fixture.hit}
  threshold: {kind: count, count: 1, window: 1m, group_by: node}
  condition: selection and threshold
auto_close: 30s
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := rules.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	first := &model.Event{TS: model.FormatTS(start), Action: "fixture.hit", Node: "fixture-node"}
	second := &model.Event{TS: model.FormatTS(start.Add(2 * time.Minute)), Action: "fixture.hit", Node: "fixture-node"}
	reg := NewRegistry(0, nil)
	created, _, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{first}), start)
	if len(created) != 1 {
		t.Fatalf("initial incident: created=%d", len(created))
	}
	oldID := created[0].IncidentID
	closed, _ := reg.Sweep(func(string) AutoClose { return AutoClose{After: r.AutoCloseAfter()} }, start.Add(30*time.Second))
	if len(closed) != 1 || closed[0].IncidentID != oldID {
		t.Fatalf("fixture must auto-close the old incident: %+v", closed)
	}
	// An unchanged replay must keep the old incident closed.
	created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{first}), start.Add(time.Minute))
	if len(created)+len(updated) != 0 {
		t.Fatal("old evidence alone reopened or rewrote the closed incident")
	}
	dets := eval.Run([]*rules.Rule{r}, []*model.Event{first, second})
	created, _, _ = reg.Apply(dets, second.Time())
	if len(created) != 1 || created[0].IncidentID == oldID {
		t.Fatalf("new evidence must open one new incident: %+v", created)
	}
	inc := created[0]
	if inc.EventCount != 1 || inc.FirstTS != second.TS || len(inc.Events) != 1 || inc.Events[0] != second {
		t.Fatalf("reopened incident reused expired evidence: first=%s count=%d; want first=%s count=1", inc.FirstTS, inc.EventCount, second.TS)
	}
}
