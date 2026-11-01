package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/enrich"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr64Round3Event() model.Event {
	return model.Event{
		TS: "2026-11-01 10:00:00.000", Source: "edr.fixture", SourceClass: "edr",
		Action: "process.start", ActorName: "fixture-account", Node: "fixture-web",
		Object: "/home/fixture/AppData/Temp/payload.exe", SrcIP: "203.0.113.7",
		Attrs: map[string]string{"name": "lsass"},
	}
}

// Use compiled rule matching and the real chain formatter, rather than making
// up an Incident.Chain row which the engine might never produce.
func pr64Round3Detect(t *testing.T, rule *rules.Rule, event model.Event) incidents.Incident {
	t.Helper()
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	event.Ensure()
	detections, _ := eval.Evaluate(eval.Input{
		Rules: []*rules.Rule{rule}, Events: []*model.Event{&event}, Now: now,
	})
	created, _, _ := incidents.NewRegistry(64000, nil).Apply(detections, now)
	if len(created) != 1 {
		t.Fatalf("fixture must match a loaded rule and create one incident, got %d", len(created))
	}
	inc := *created[0]
	inc.Status = incidents.StatusClosed
	if inc.PII != 0 {
		t.Fatal("fixture must reach the pii=0 export path")
	}
	return inc
}

func TestPR64Round3EventTokensDoNotDiscloseIdentifiers(t *testing.T) {
	rule, err := rules.LoadFile(filepath.Join("..", "..", "..", "rules", "lsass-access.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, source, action, private string
	}{
		// /ingest/events accepts source/action strings, including custom
		// source names; they are not enums (collector/internal/listen/http.go).
		{"source", "edr.alice-pc", "process.start", "alice-pc"},
		// FromCEF/actionOutcome also derives actions from a free-text category:
		// cat=alice.smirnov becomes event.alice_smirnov, with pii=0.
		{"action", "edr.fixture", "event.alice_smirnov", "alice_smirnov"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, enrichment := range []bool{false, true} {
				name := "chain"
				if enrichment {
					name = "enrichment"
				}
				t.Run(name, func(t *testing.T) {
					event := pr64Round3Event()
					event.Source, event.Action = tc.source, tc.action
					inc := pr64Round3Detect(t, rule, event)
					lines := inc.Chain
					if enrichment {
						// Isolate the enrichment route from Sources and Chain.
						inc = pr64PrivacyIncident()
						inc.Node = event.Node
						inc.Enrichment = enrich.New(pr64EnrichmentSource{events: []*model.Event{&event}}, "").Run(
							context.Background(), &inc, []any{"edr.process_tree"})
						lines = inc.Enrichment
					}
					if !strings.Contains(strings.Join(lines, "\n"), tc.private) {
						t.Fatal("private fixture must reach the production formatter")
					}
					// The existing helper captures Decide through an in-memory
					// RoundTripper and checks both the Jev body and the JSONL.
					pr64AssertNoPrivateState(t, inc, tc.private)
				})
			}
		})
	}
}
