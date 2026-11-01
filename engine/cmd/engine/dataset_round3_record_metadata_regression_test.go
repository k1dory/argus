package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/dataset"
)

func TestPR64Round3JSONLDoesNotRestoreRedactedRuleMetadata(t *testing.T) {
	const email = "alice.smirnov@example.invalid"
	rule := pr64Round3LoadRule(t, `
id: pr64-rule-tags
title: File access
level: high
tags: [attack.credential_access, 'owner:alice.smirnov@example.invalid']
detection:
  selection:
    source.class: edr
  condition: selection
`)
	inc := pr64Round3Detect(t, rule, pr64Round3Event())
	// Positive control: this email is already removed from the model state.
	// The finding is the independent raw metadata path in dataset.Build.
	if strings.Contains(analyst.DecisionState(&inc), email) {
		t.Fatal("fixture must isolate JSONL metadata from model-state redaction")
	}
	states, output := pr64ExportToJev(t, inc)
	for _, state := range states {
		if strings.Contains(state, email) {
			t.Error("Jev received the private rule tag")
		}
	}
	var record dataset.Record
	if err := json.Unmarshal([]byte(output), &record); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, email) {
		t.Errorf("JSONL restored the private rule tag outside state: tags=%q", record.Tags)
	}
}
