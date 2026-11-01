package eval

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// QNAP local usernames are scoped to a NAS. Identically named local accounts
// on independent appliances must not pool their activity into one threshold
// or one incident attributed to the first appliance.
func TestNASMassFileChangeKeepsLocalAccountsSeparate(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/nas-mass-file-change.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, secondNode string
		perNode, want    int
	}{
		{"two independent users below threshold", "NAS-B", 100, 0},
		{"two independent users above threshold", "NAS-B", 200, 2},
		{"same NAS reaches threshold", "NAS-A", 100, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
			var events []*model.Event
			for i := 0; i < tc.perNode; i++ {
				for _, node := range []string{"NAS-A", tc.secondNode} {
					events = append(events, &model.Event{
						TS:     model.FormatTS(start.Add(time.Duration(i) * time.Second)),
						Source: "nas.qnap", SourceClass: "storage", Action: "file.delete", Outcome: "success",
						ActorName: "admin", ActorKind: "user", Node: node,
						Object: fmt.Sprintf("Public/report-%d.txt", len(events)),
					})
				}
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != tc.want {
				t.Fatalf("%d operations per NAS by unrelated local admin accounts: detections=%d, want %d", tc.perNode, len(dets), tc.want)
			}
			for _, d := range dets {
				node := d.Events[0].Node
				for _, event := range d.Events {
					if event.Node != node {
						t.Fatalf("local-account detection mixes appliances %q and %q", node, event.Node)
					}
				}
			}
		})
	}
}
