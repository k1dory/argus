package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/attack"
	"github.com/devitex-soft/argus/engine/internal/incidents"
)

func TestPR72ExportKeepsValidTaggedTechniqueAvailableToTheModel(t *testing.T) {
	const tactic, technique = "credential-access", "T1558.003"
	for _, tc := range []struct {
		name, tacticTag, techniqueTag string
	}{
		{"canonical_control", "attack.credential_access", "attack.t1558.003"},
		{"uppercase_prefix", "attack.credential_access", "ATTACK.T1558.003"},
		{"mixed_case", "Attack.Credential_Access", "attack.T1558.003"},
		{"surrounding_space", " attack.credential_access ", " attack.t1558.003 "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The loader and the shared UI/Go candidate contract accept these
			// equivalent spellings. Use a subtechnique outside the untagged
			// tactic's first 20 options so loss of the tag has an observable cost.
			rule := pr64Round3LoadRule(t, fmt.Sprintf(`
id: pr72-candidate-tags
title: Credential access
level: high
tags: [%q, %q]
detection:
  selection:
    source.class: edr
  condition: selection
`, tc.tacticTag, tc.techniqueTag))
			inc := pr64Round3Detect(t, rule, pr64Round3Event())
			if !slices.Contains(attack.Candidates(inc.Tags, tactic), technique) ||
				slices.Contains(attack.Candidates(nil, tactic), technique) {
				t.Fatal("fixture must offer the tagged technique only when the tag is retained")
			}
			escalate, severity := false, 2
			label := &closureLabel{Disposition: "malicious", Escalate: &escalate, SeverityLevel: &severity,
				AttackTactic: tactic, AttackTechnique: technique}
			if err := validateLabel(&inc, incidents.StatusClosed, label); err != nil {
				t.Fatalf("ordinary human closure must be accepted: %v", err)
			}
			row := labeled("INC-72002", 0, true)
			row.Incident, row.Label = inc, storeLabel(&inc, label)
			client := pr64Round5GroupModel(t, tactic, technique)
			var output bytes.Buffer
			stats, err := exportDataset(context.Background(), fakeLabeled{row}, &output,
				datasetOpts{Source: "prod", Models: []string{"laya"}}, client, nil)
			if err != nil || stats.Written != 1 || stats.ModelErrors != 0 {
				t.Fatalf("export: %v; stats=%+v", err, stats)
			}
			records := readRecords(t, &output)
			if len(records) != 1 {
				t.Fatalf("expected one record, got %d", len(records))
			}
			r := records[0]
			if r.Models["laya"].Answers["attack_tactic"].Choice != tactic {
				t.Fatal("model and analyst must choose the same tactic")
			}
			if r.Labels["attack_technique"] != technique ||
				!slices.Contains(r.Questions["attack_technique"].Options(), technique) {
				t.Fatal("the accepted tagged target must be retained for training")
			}
			if !slices.Contains(r.Question("laya", "attack_technique").Options(), technique) {
				t.Errorf("anonymization removed %s from the actual model question despite matching tactic; exported tags=%v",
					technique, r.Tags)
			}
			if got := r.Models["laya"].Answers["attack_technique"].Choice; got != technique {
				t.Errorf("model was forced to answer %q instead of the offered human target %s", got, technique)
			}
		})
	}
}
