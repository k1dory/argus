package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Run only against a disposable, isolated ClickHouse using the existing
// ARGUS_TEST_CLICKHOUSE_URL convention. All data belongs to a fresh database;
// neither production tables nor the shared argus test database are modified.
func TestPR64LabeledIncidentsSinceKeepsSubmillisecondBoundary(t *testing.T) {
	configured := liveStore(t)
	db := "argus_pr64_labels_since_" + suffix(t)
	sys := New(configured.base, "default", configured.user, configured.pass)
	exec(t, sys, "CREATE DATABASE "+db)
	t.Cleanup(func() {
		if _, err := sys.do(context.Background(), "DROP DATABASE "+db+" SYNC", nil, nil); err != nil {
			t.Errorf("cleanup fixture database: %v", err)
		}
	})
	c := New(configured.base, db, configured.user, configured.pass)
	// Use the actual migrations, including the incidents_current view.
	for _, migration := range []struct {
		file     string
		prefixes []string
	}{
		{"0005_events_incidents.sql", []string{"CREATE TABLE IF NOT EXISTS argus.incidents\n"}},
		{"0006_ops_feedback.sql", []string{"ALTER TABLE argus.incidents "}},
		{"0014_incident_state_events.sql", []string{"CREATE TABLE IF NOT EXISTS argus.incident_state_events", "CREATE VIEW IF NOT EXISTS argus.incidents_current"}},
		{"0016_incident_closure_reason.sql", []string{"ALTER TABLE argus.incident_state_events "}},
		{"0033_incident_labels.sql", []string{"ALTER TABLE argus.incident_state_events\n"}},
		{"0036_incident_label_plan.sql", []string{"ALTER TABLE argus.incident_state_events\n"}},
	} {
		path := filepath.Join("..", "..", "..", "clickhouse", "migrations", migration.file)
		matched := 0
		for _, statement := range migrationStatements(t, path) {
			for _, prefix := range migration.prefixes {
				if strings.HasPrefix(statement, prefix) {
					exec(t, c, strings.ReplaceAll(statement, "argus.", db+"."))
					matched++
					break
				}
			}
		}
		if matched < len(migration.prefixes) {
			t.Fatalf("fixture DDL not found in %s", migration.file)
		}
	}
	const earlyID, lateID = "INC-64001", "INC-64002"
	ctx := context.Background()
	for i, id := range []string{earlyID, lateID} {
		inc := &incidents.Incident{
			IncidentID: id, RuleID: "pr64-since", RuleTitle: "Since fixture", Level: "high",
			Status: incidents.StatusNew, UpdatedAt: "2099-01-01 00:00:00", CreatedAt: "2099-01-01 00:00:00",
			FirstTS: "2099-01-01 00:00:00.000", LastTS: "2099-01-01 00:00:00.000",
			Tags: []string{}, Sources: []string{}, Chain: []string{}, Enrichment: []string{}, Similar: []string{},
		}
		if err := c.InsertIncidents(ctx, []*incidents.Incident{inc}); err != nil {
			t.Fatal(err)
		}
		eventID, err := newEventID()
		if err != nil {
			t.Fatal(err)
		}
		at := []string{"2099-01-01 00:00:00.123", "2099-01-01 00:00:00.124"}[i]
		if err := c.insert(ctx, "incident_state_events", []any{IncidentStateEvent{
			EventID: eventID, IncidentID: id, Revision: 1, ChangedAt: at,
			Actor: "fixture-analyst", Kind: "status", Status: incidents.StatusClosed,
			ClosureLabel: ClosureLabel{Disposition: "malicious", LabeledByHuman: true},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		since string
		ids   []string
	}{
		{"2099-01-01T00:00:00.123000000Z", []string{earlyID, lateID}},
		{"2099-01-01T00:00:00.1231Z", []string{lateID}},
		{"2099-01-01T00:00:00.123000001Z", []string{lateID}},
		{"2099-01-01T00:00:00.124Z", []string{lateID}},
	} {
		t.Run(tc.since, func(t *testing.T) {
			rows, err := c.LabeledIncidents(ctx, tc.since, 10)
			if err != nil {
				t.Fatal(err)
			}
			var ids []string
			for _, row := range rows {
				ids = append(ids, row.Incident.IncidentID)
			}
			if strings.Join(ids, ",") != strings.Join(tc.ids, ",") {
				t.Errorf("since=%s: got %v, want %v; labels before the boundary must not be exported", tc.since, ids, tc.ids)
			}
		})
	}
}
