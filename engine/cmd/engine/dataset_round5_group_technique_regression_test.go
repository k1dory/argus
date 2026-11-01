package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/attack"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
	"github.com/devitex-soft/argus/engine/internal/systemone"
)

func TestPR64Round5ScanGroupTechniqueRemainsAnAvailableTarget(t *testing.T) {
	var group []incidents.Incident
	var groupTags []string
	for i, file := range []string{"net-inbound-portscan.yml", "net-inbound-sweep.yml"} {
		rule, err := rules.LoadFile(filepath.Join("..", "..", "..", "rules", file))
		if err != nil {
			t.Fatal(err)
		}
		group = append(group, incidents.Incident{
			IncidentID: fmt.Sprintf("INC-%d", 64510+i), RuleID: rule.ID, RuleTitle: rule.Title, Level: rule.Level,
			Tags: rule.Tags, Status: incidents.StatusInProgress, Owner: "fixture-analyst",
			ActorName: fmt.Sprintf("203.0.113.%d", 10+i), Sources: []string{"netflow"},
		})
		for _, tag := range rule.Tags {
			if !slices.Contains(groupTags, tag) {
				groupTags = append(groupTags, tag)
			}
		}
	}

	// Both shipped rules belong to SCAN_GROUP_RULES. The ordinary group UI
	// calls attackFormOptions on the UNION of the displayed incident tags
	// (web/src/app/(console)/incidents/page.tsx). scanGroupAction then applies
	// ONE selected label to every incident, with the normal workflow checks.
	const tactic = "reconnaissance"
	for _, technique := range []string{"T1046", "T1595.001"} {
		t.Run(technique, func(t *testing.T) {
			if !slices.Contains(attack.Candidates(groupTags, tactic), technique) {
				t.Fatalf("fixture choice %s must be offered by the group form", technique)
			}
			escalate, severity := false, 2
			label := &closureLabel{
				Disposition: "malicious", Escalate: &escalate, SeverityLevel: &severity,
				AttackTactic: tactic, AttackTechnique: technique,
			}
			var rows fakeLabeled
			controlID := ""
			for _, inc := range group {
				status, owner, err := workflowDecision(&inc, workflowRequest{
					Actor: inc.Owner, Role: "analyst", Kind: "status", Status: incidents.StatusClosed,
					Reason: "Confirmed reconnaissance of the monitored network", Label: label,
				})
				if err != nil {
					t.Fatalf("group closure for %s must pass the real workflow: %v", inc.RuleID, err)
				}
				inc.Status, inc.Owner = status, owner
				rows = append(rows, store.LabeledIncident{
					Incident: inc, Label: storeLabel(&inc, label), ChangedAt: "2026-11-01 16:00:00.000",
				})
				if slices.Contains(attack.RuleTechniques(inc.Tags), technique) {
					controlID = inc.IncidentID
				}
			}
			if controlID == "" {
				t.Fatal("one group member must have the selected technique in its own tags")
			}

			// Answer the tactic correctly. This isolates candidate loss from an
			// ordinary model mistake in the first stage. The in-memory transport
			// returns a valid distribution for every actual question; no sockets
			// or real model endpoints are used.
			client := pr64Round5GroupModel(t, tactic, technique)
			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), rows, &output,
				datasetOpts{Source: "prod", Models: []string{"laya"}}, client, nil)
			if err != nil || stats.ModelErrors != 0 {
				t.Fatalf("export: %v; stats=%+v", err, stats)
			}
			controlSeen := false
			for _, record := range readRecords(t, &output) {
				if record.IncidentID == controlID {
					controlSeen = true
					if record.Labels["attack_technique"] != technique {
						t.Errorf("valid tagged technique was lost: %v", record.Labels)
					}
				}
				if got := record.Models["laya"].Answers["attack_tactic"].Choice; got != tactic {
					t.Fatalf("model must choose the same tactic as the human: got %q", got)
				}
				// Omitting an unsupported target (or the affected record) is safe;
				// emitting a training label that the question cannot express is not.
				if target, ok := record.Labels["attack_technique"]; ok {
					for source, question := range map[string]systemone.Question{
						"training": record.Questions["attack_technique"],
						"model":    record.Question("laya", "attack_technique"),
					} {
						if !slices.Contains(question.Options(), target) {
							t.Errorf("%s: accepted group technique %q is outside %s options %v despite matching tactic %q",
								record.RuleID, target, source, question.Options(), tactic)
						}
					}
				}
			}
			if !controlSeen {
				t.Fatal("the group member with a valid tagged technique must still be exported")
			}
		})
	}
}

func pr64Round5GroupModel(t *testing.T, tactic, technique string) *systemone.Client {
	t.Helper()
	return &systemone.Client{
		Name: "laya", Endpoint: "https://model.example.invalid/v1/systemone", Model: "fixture-model",
		HTTP: &http.Client{Transport: pr64DatasetTransport(func(req *http.Request) (*http.Response, error) {
			var payload struct {
				Questions map[string]systemone.Question `json:"questions"`
			}
			if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			answers := make(map[string]systemone.Answer, len(payload.Questions))
			for id, q := range payload.Questions {
				a := systemone.Answer{Type: q.Type}
				switch q.Type {
				case systemone.Noul:
					no := 0.0
					a.Noul = &no
				case systemone.Choice, systemone.Score:
					chosen := map[string]string{
						"disposition": "malicious", "attack_tactic": tactic,
						"attack_technique": technique, "severity_level": "1",
					}[id]
					if id == "attack_technique" && !slices.Contains(q.Options(), chosen) {
						chosen = attack.Other
					}
					if !slices.Contains(q.Options(), chosen) {
						t.Fatalf("fixture has no valid answer for %s: %v", id, q.Options())
					}
					a.Probabilities = make(map[string]float64, len(q.Options()))
					for _, option := range q.Options() {
						a.Probabilities[option] = 0
					}
					a.Probabilities[chosen] = 1
					if q.Type == systemone.Choice {
						a.Choice = chosen
					} else {
						score := 1.0
						a.Score = &score
					}
				default:
					t.Fatalf("unexpected question type %q", q.Type)
				}
				answers[id] = a
			}
			body, err := json.Marshal(systemone.Response{Model: "fixture-model", Answers: answers})
			if err != nil {
				t.Fatal(err)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), Request: req,
			}, nil
		})},
	}
}
