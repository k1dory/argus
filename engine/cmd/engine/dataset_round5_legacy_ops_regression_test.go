package main

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func TestPR64Round5LegacyOpsLabelsDoNotBecomeV2Targets(t *testing.T) {
	rule, err := rules.LoadFile(filepath.Join("..", "..", "..", "rules", "ops", "disk-usage-high.yml"))
	if err != nil {
		t.Fatal(err)
	}
	inc := incidents.Incident{
		IncidentID: "INC-64501", RuleID: rule.ID, RuleTitle: rule.Title, Level: rule.Level,
		Tags: rule.Tags, Status: incidents.StatusClosed, Node: "fixture-db",
	}

	// These were accepted human closures in release/1.0.0-rc31 (0a352a3,
	// labels.go from ef8585e). Migration 0036 adds nullable columns without
	// rewriting ops_cause or labeled_by_human. LabeledIncidents still returns
	// these rows, and dataset export defaults to --since 1970-01-01.
	for _, cause := range []string{"real_failure", "planned_work", "monitoring_noise", "wrong_threshold"} {
		t.Run(cause, func(t *testing.T) {
			legacy := store.LabeledIncident{
				Incident: inc,
				Label: store.ClosureLabel{
					OpsCause: cause, OpsAction: "fixed", Blind: true, LabeledByHuman: true,
				},
				ChangedAt: "2026-11-01 02:10:00.000",
			}
			// Preserve a valid current closure as a positive control: dropping
			// every ops record must not make this regression test pass.
			current := inc
			current.IncidentID = "INC-64502"
			actNow, urgency := true, 3
			label := &closureLabel{OpsCause: "disk", OpsActNow: &actNow, OpsUrgency: &urgency}
			if err := validateLabel(&current, current.Status, label); err != nil {
				t.Fatalf("current closure must be accepted: %v", err)
			}
			rows := fakeLabeled{legacy, {
				Incident: current, Label: storeLabel(&current, label), ChangedAt: "2026-11-01 15:10:00.000",
			}}
			var output bytes.Buffer
			if _, err := exportDataset(context.Background(), rows, &output,
				datasetOpts{Since: "1970-01-01", Limit: 50000, Source: "prod"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			currentSeen := false
			for _, record := range readRecords(t, &output) {
				if record.Schema != dataset.Schema || record.Scenario != dataset.Ops {
					t.Fatalf("unexpected exported record: %+v", record)
				}
				if record.IncidentID == current.IncidentID {
					currentSeen = true
					if record.Labels["ops_cause"] != "disk" || record.Labels["ops_act_now"] != "true" || record.Labels["ops_urgency"] != "2" {
						t.Errorf("valid current closure was lost: %v", record.Labels)
					}
				}
				if target, ok := record.Labels["ops_cause"]; ok && !slices.Contains(record.Questions["ops_cause"].Options(), target) {
					t.Errorf("persisted pre-0036 closure %q became a %s target outside model options %v",
						target, record.Schema, record.Questions["ops_cause"].Options())
				}
			}
			if !currentSeen {
				t.Fatal("valid current ops closure must remain in the dataset")
			}
		})
	}
}
