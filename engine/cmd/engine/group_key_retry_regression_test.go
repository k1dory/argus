package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// A failed INSERT must leave adoption pending. Otherwise an unchanged replay
// never writes the group key again, and the next restart treats this disk's
// incident as an ungrouped legacy incident that another disk can take over.
func TestGroupKeyAdoptionRetriesAfterInsertFailure(t *testing.T) {
	raw, err := os.ReadFile("../../../rules/ops/nas-storage-failure.yml")
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"nas.yml": string(raw)}), respond.Config{}, "test-token", "test-metrics")
	rs := e.current()
	now := time.Now().UTC().Truncate(time.Second)
	ev := &model.Event{
		TS: model.FormatTS(now.Add(-time.Minute)), Source: "nas.qnap", SourceClass: "storage",
		Action: "storage.event", Outcome: "failure", ActorName: "System", Node: "QNAP-2",
		Object: "[Storage & Snapshots] Host: Disk 3: Medium error.",
	}
	legacy := incidents.Incident{
		IncidentID: "INC-7", RuleID: rs[0].ID, RuleTitle: rs[0].Title, Level: "high",
		Status: incidents.StatusNew, ActorName: ev.ActorName, Node: ev.Node,
		EventCount: 1, FirstTS: ev.TS, LastTS: ev.TS,
		CreatedAt: ev.TS[:19], UpdatedAt: ev.TS[:19],
	}
	e.reg = incidents.NewRegistry(7, []incidents.Incident{legacy})
	operator, err := json.Marshal(map[string]string{
		"incident_id": legacy.IncidentID, "status": legacy.Status, "updated_max": legacy.UpdatedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.selects["FROM incidents_current"] = string(operator)
	f.fail["incidents"] = true
	buffer := []*model.Event{ev}
	e.cycle(context.Background(), rs, buffer)
	if rows := f.rows("incidents"); len(rows) != 0 {
		t.Fatalf("the failed INSERT unexpectedly persisted rows: %v", rows)
	}

	// ClickHouse has recovered; the evidence is unchanged on the next poll.
	f.mu.Lock()
	f.fail["incidents"] = false
	f.mu.Unlock()
	e.cycle(context.Background(), rs, buffer)
	rows := f.rows("incidents")
	if len(rows) != 1 {
		t.Fatalf("group-key adoption must be retried after INSERT failure without requiring new evidence: persisted rows=%d, want 1", len(rows))
	}
	var persisted incidents.Incident
	if err := json.Unmarshal([]byte(rows[0]), &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.IncidentID != legacy.IncidentID || persisted.GroupKey == "" || persisted.UpdatedAt <= legacy.UpdatedAt {
		t.Fatalf("retry must persist the same incident with its group and a newer row version: %+v", persisted)
	}
}
