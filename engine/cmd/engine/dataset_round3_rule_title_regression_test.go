package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr64Round3LoadRule(t *testing.T, document string) *rules.Rule {
	t.Helper()
	path := filepath.Join(t.TempDir(), "privacy-rule.yml")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	rule, err := rules.LoadFile(path)
	if err != nil {
		t.Fatalf("fixture must be accepted by the production rule loader: %v", err)
	}
	return rule
}

func TestPR64Round3RuleTitleDoesNotDiscloseNamesOrHosts(t *testing.T) {
	// Custom operational rule titles can name an employee or a monitored host.
	// The loader accepts them, and incident pii is derived from events, not
	// from rule metadata. Neither names nor hostnames match redactPII's regexes.
	rule := pr64Round3LoadRule(t, `
id: pr64-rule-title
title: 'File access by Иван Петров on audit-alice.corp (10.64.12.34)'
level: high
tags: [attack.credential_access]
detection:
  selection:
    source.class: edr
  condition: selection
`)
	inc := pr64Round3Detect(t, rule, pr64Round3Event())
	pr64AssertNoPrivateState(t, inc, "Иван Петров", "audit-alice.corp", "10.64.12.34")
}
