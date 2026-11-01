package main

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/attack"
	"github.com/devitex-soft/argus/engine/internal/dataset"
)

func TestPR72ExportDoesNotTreatPrivateNamesAsAttackTactics(t *testing.T) {
	const privateTag = "attack.alice_smirnov"
	if attack.Tactic("alice-smirnov") {
		t.Fatal("the private fixture must not be an ATT&CK tactic")
	}
	for _, ruleID := range []string{"pr72-private-tag", "a41c-auth-031"} {
		t.Run(ruleID, func(t *testing.T) {
			// Both a custom rule and a locally edited shipped rule can carry
			// operator metadata. Rule metadata does not set the event PII bit.
			rule := pr64Round3LoadRule(t, fmt.Sprintf(`
id: %s
title: Authentication activity
level: high
tags: [attack.credential_access, attack.t1110.001, %s]
detection:
  selection:
    source.class: edr
  condition: selection
`, ruleID, privateTag))
			inc := pr64Round3Detect(t, rule, pr64Round3Event())
			if !slices.Contains(inc.Tags, privateTag) {
				t.Fatal("fixture must reach the real incident with its private tag")
			}

			// Capture exportDataset -> Decide after production sanitization.
			// The helper uses an in-memory RoundTripper and never opens a socket.
			states, output := pr64ExportToJev(t, inc)
			if len(states) != 1 {
				t.Fatalf("expected one captured Jev request, got %d", len(states))
			}
			if strings.Contains(states[0], "alice_smirnov") {
				t.Error("Jev received the private name from a nonexistent ATT&CK tactic")
			}
			if strings.Contains(output, "alice_smirnov") {
				t.Error("JSONL contains the private name in state or tags")
			}
			var record dataset.Record
			if err := json.Unmarshal([]byte(output), &record); err != nil {
				t.Fatal(err)
			}
			for _, valid := range []string{"attack.credential_access", "attack.t1110.001"} {
				if !strings.Contains(states[0], valid) || !slices.Contains(record.Tags, valid) {
					t.Errorf("known ATT&CK tag %q must survive anonymization", valid)
				}
			}
		})
	}
}
