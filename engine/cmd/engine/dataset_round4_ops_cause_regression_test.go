package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/dataset"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func TestPR64Round4OpsDatasetLabelsAreModelOptions(t *testing.T) {
	// An unchanged shipped rule and ordinary telemetry create the incident.
	// Exercise the actual closure validator and stored label conversion: no
	// obsolete or invented labels are inserted directly into a dataset.Record.
	rule, err := rules.LoadFile(filepath.Join("..", "..", "..", "rules", "ops", "disk-usage-high.yml"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var events []*model.Event
	for i := 0; i < 3; i++ {
		e := &model.Event{
			TS:     model.FormatTS(now.Add(time.Duration(i-2) * time.Minute)),
			Source: "telemetry.node", SourceClass: "telemetry", Action: "disk.usage",
			Node: "fixture-db", Object: "/var/lib/clickhouse", Value: 91 + float64(i), Unit: "percent",
		}
		e.Ensure()
		events = append(events, e)
	}
	detections, _ := eval.Evaluate(eval.Input{Rules: []*rules.Rule{rule}, Events: events, Now: now})
	created, _, _ := incidents.NewRegistry(64000, nil).Apply(detections, now)
	if len(created) != 1 || !opsIncident(created[0]) || created[0].PII != 0 {
		t.Fatalf("expected one ordinary ops incident, got %+v", created)
	}

	// Use the production form's complete vocabulary, rather than repeating the
	// dataset's own constants (which would conceal a contract mismatch).
	for _, cause := range opsCauses {
		t.Run(cause, func(t *testing.T) {
			inc := *created[0]
			inc.Status = incidents.StatusClosed
			if cause == "false_positive" {
				inc.Status = incidents.StatusFalsePositive
			}
			actNow, urgency := true, 2
			label := &closureLabel{OpsCause: cause, OpsActNow: &actNow, OpsUrgency: &urgency}
			if err := validateLabel(&inc, inc.Status, label); err != nil {
				t.Fatalf("fixture must be accepted by the current closure API: %v", err)
			}
			rows := fakeLabeled{{Incident: inc, Label: storeLabel(&inc, label), ChangedAt: model.FormatTS(now)}}
			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), rows, &output, datasetOpts{Source: "prod"}, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if stats.Written != 1 {
				t.Fatalf("accepted human closure must be exported, stats=%+v", stats)
			}
			// Inspect the actual JSONL contract. A training target must be one of
			// the choices offered to the model; otherwise even a perfect model
			// cannot reproduce it, and evaluation always counts it as wrong.
			var record struct {
				Scenario  string            `json:"scenario"`
				Labels    map[string]string `json:"labels"`
				Questions map[string]struct {
					Type string `json:"type"`
					// Score-вопросы v2 (severity_level, ops_urgency) несут шкалу
					// массивом — разбираем criteria только у проверяемого вопроса.
					Criteria json.RawMessage `json:"criteria"`
				} `json:"questions"`
			}
			if err := json.Unmarshal(output.Bytes(), &record); err != nil {
				t.Fatal(err)
			}
			if record.Scenario != dataset.Ops || record.Labels["ops_cause"] == "" {
				t.Fatalf("expected a labeled ops record: %+v", record)
			}
			question, ok := record.Questions["ops_cause"]
			if !ok || question.Type != "choice" {
				t.Fatalf("export must ask the model for the labeled ops cause: %+v", record.Questions)
			}
			var choices map[string]string
			if err := json.Unmarshal(question.Criteria, &choices); err != nil {
				t.Fatalf("ops_cause criteria: %v", err)
			}
			if _, ok := choices[record.Labels["ops_cause"]]; !ok {
				t.Errorf("accepted closure cause %q became JSONL label %q outside model choices %v",
					cause, record.Labels["ops_cause"], choices)
			}
		})
	}
}
