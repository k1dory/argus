package incidents

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func qnapStorageEvent(node string, disk, minute int) *model.Event {
	e := &model.Event{
		TS: fmt.Sprintf("2026-10-30 12:%02d:00.000", minute), Source: "nas.qnap", SourceClass: "storage",
		Action: "storage.event", Outcome: "failure", Severity: 4, Node: node, ActorName: "System", ActorKind: "user", SrcIP: "127.0.0.1",
		Object: fmt.Sprintf("[Storage & Snapshots] Host: Disk %d: Medium error. Run a bad block scan on the drive.", disk),
		Attrs:  map[string]string{"log": "event", "application": "Storage & Snapshots", "category": "Disk"},
	}
	e.Ensure()
	return e
}

func qnapStorageRule(t *testing.T) *rules.Rule {
	t.Helper()
	r, err := rules.LoadFile("../../../rules/ops/nas-storage-failure.yml")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestQNAPStorageFailureSeparatesDevices(t *testing.T) {
	r := qnapStorageRule(t)
	for _, tc := range []struct {
		name, secondNode string
		secondDisk, want int
	}{
		{"same disk on different NAS", "QNAP-3", 3, 2},
		{"different disks on the same NAS", "QNAP-2", 4, 2},
		{"repeat of the same disk", "QNAP-2", 3, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []*model.Event{qnapStorageEvent("QNAP-2", 3, 0), qnapStorageEvent(tc.secondNode, tc.secondDisk, 1)}
			dets := eval.Run([]*rules.Rule{r}, events)
			if len(dets) != tc.want {
				t.Fatalf("detections=%d, want %d; distinct NAS/disks must not share the System user's daily dedupe group: %+v", len(dets), tc.want, dets)
			}
			if tc.want == 2 && (dets[0].Key == dets[1].Key || len(dets[0].Events) != 1 || len(dets[1].Events) != 1) {
				t.Fatalf("separate devices need independent groups/evidence: %+v", dets)
			}
			if tc.want == 1 && len(dets[0].Events) != 2 {
				t.Fatalf("a repeated fault must retain both evidence records: %+v", dets)
			}
		})
	}
}

// The first fault has already opened an incident. The engine retains both
// events in its next evaluation cycle and notifies only about created incidents.
func TestQNAPSecondNASFaultCreatesNewIncident(t *testing.T) {
	r := qnapStorageRule(t)
	reg := NewRegistry(0, nil)
	first := qnapStorageEvent("QNAP-2", 3, 0)
	created, _, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{first}), first.Time().Add(time.Second))
	if len(created) != 1 || created[0].Node != "QNAP-2" {
		t.Fatalf("initial incident: %+v", created)
	}
	firstID := created[0].IncidentID
	second := qnapStorageEvent("QNAP-3", 3, 1)
	created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{first, second}), second.Time().Add(time.Second))
	if len(created) != 1 {
		t.Fatalf("second NAS fault needs its own incident/notification: created=%d updated=%d, first incident=%s; updating the first NAS incident is insufficient", len(created), len(updated), firstID)
	}
	if created[0].Node != "QNAP-3" || created[0].IncidentID == firstID || created[0].EventCount != 1 {
		t.Fatalf("wrong identity or mixed evidence for second NAS: %+v", created[0])
	}
}
