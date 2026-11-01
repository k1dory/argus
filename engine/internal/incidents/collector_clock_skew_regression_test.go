package incidents

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr80ClockSkewFixture(t *testing.T) (*rules.Rule, []*model.Event) {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	rule, err := rules.LoadFile(filepath.Join(root, "rules", "ops", "collector-clock-skew.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if rule.ID != "a41c-ops-067" {
		t.Fatalf("unexpected rule: %q", rule.ID)
	}
	raw, err := os.ReadFile(filepath.Join(root, "fixtures", "events", "collector-clock-skew.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	var events []*model.Event
	for line, data := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var event model.Event
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatalf("fixture line %d: %v", line+1, err)
		}
		event.Ensure()
		events = append(events, &event)
	}
	return rule, events
}

// The YAML runner counts detections and calls Detection.Key expect_actor.
// Also check real incidents, their level, peer isolation, repeated evaluation,
// and restart with a persisted group key. No ClickHouse connection is needed.
func TestPR80ClockSkewFixtureCreatesTwoLowIncidents(t *testing.T) {
	rule, events := pr80ClockSkewFixture(t)
	if rule.Window() != 24*time.Hour || rule.GroupBy() != "attrs.peer" {
		t.Fatalf("unexpected dedupe contract: window=%s group_by=%q", rule.Window(), rule.GroupBy())
	}
	detections := eval.Run([]*rules.Rule{rule}, events)
	wantCounts := map[string]int{"192.168.0.30": 3, "192.168.0.31": 1}
	if len(detections) != len(wantCounts) {
		t.Fatalf("fixture: got %d detections, want %d", len(detections), len(wantCounts))
	}
	seen := map[string]bool{}
	for _, d := range detections {
		want, ok := wantCounts[d.Key]
		if !ok || seen[d.Key] || len(d.Events) != want {
			t.Fatalf("unexpected group: key=%q events=%d duplicate=%t", d.Key, len(d.Events), seen[d.Key])
		}
		seen[d.Key] = true
		for _, e := range d.Events {
			if e.Attrs["transport"] != "internal" || e.Attrs["peer"] != d.Key {
				t.Fatalf("mixed or external evidence in peer %q: %+v", d.Key, e)
			}
		}
	}
	now := time.Date(2026, 11, 1, 18, 1, 0, 0, time.UTC)
	registry := NewRegistry(0, nil)
	created, updated, dropped := registry.Apply(detections, now)
	if len(created) != 2 || len(updated) != 0 || len(dropped) != 0 {
		t.Fatalf("fixture incidents: created=%d updated=%d dropped=%v", len(created), len(updated), dropped)
	}
	var persisted []Incident
	for _, inc := range created {
		if inc.Level != "low" || inc.Status != StatusNew || int(inc.EventCount) != wantCounts[inc.GroupKey] {
			t.Fatalf("incorrect level, status or peer evidence: %+v", inc)
		}
		row := *inc
		row.Events = nil // Events is not persisted; group_key must survive by itself.
		persisted = append(persisted, row)
	}
	for name, reg := range map[string]*Registry{
		"next_cycle": registry,
		"restart":    NewRegistry(2, persisted),
	} {
		t.Run(name, func(t *testing.T) {
			created, updated, _ := reg.Apply(detections, now.Add(time.Minute))
			if len(created) != 0 || len(updated) != 0 {
				t.Fatalf("unchanged fixture must not create or rewrite incidents: created=%d updated=%d", len(created), len(updated))
			}
		})
	}
}

func TestPR80ClockSkewSelectionRejectsExternalOrigin(t *testing.T) {
	rule, events := pr80ClockSkewFixture(t)
	for _, transport := range []string{"internal", "http", "ingest", "udp", "tcp", "tls", "file", "pull", ""} {
		t.Run(transport, func(t *testing.T) {
			event := *events[0]
			event.Attrs = map[string]string{"peer": events[0].Attrs["peer"], "transport": transport}
			detections, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{rule}, Events: []*model.Event{&event}})
			want := 0
			if transport == "internal" {
				want = 1
			}
			if len(detections) != want || len(closers) != 0 {
				t.Fatalf("transport=%q: detections=%d want=%d closers=%d", transport, len(detections), want, len(closers))
			}
		})
	}
}

func TestPR80ClockSkewDedupeIncludes24HourBoundary(t *testing.T) {
	rule, fixture := pr80ClockSkewFixture(t)
	first := fixture[0]
	var events []*model.Event
	for _, offset := range []time.Duration{0, 23*time.Hour + 59*time.Minute, 24 * time.Hour, 24*time.Hour + time.Second} {
		event := *first
		event.TS = model.FormatTS(first.Time().Add(offset))
		events = append(events, &event)
	}
	detections := eval.Run([]*rules.Rule{rule}, events)
	if len(detections) != 2 || len(detections[0].Events) != 3 || len(detections[1].Events) != 1 {
		t.Fatalf("same peer: want three events in the first 24h window and a new detection after it; got %+v", detections)
	}
	for _, d := range detections {
		if d.Key != first.Attrs["peer"] {
			t.Fatalf("dedupe changed peer: %q", d.Key)
		}
	}
}

// The affected device must be visible in the operational alert. group_key is
// used internally for dedupe, but neither notifyIncident's message nor the web
// incident card displays it. The actual fixture gives both ActorName and Node
// the value argus-collector, and chain() currently discards attrs.peer.
func TestPR80ClockSkewIncidentShowsAffectedPeer(t *testing.T) {
	rule, events := pr80ClockSkewFixture(t)
	created, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{rule}, events), events[len(events)-1].Time())
	if len(created) != 2 {
		t.Fatalf("fixture must create two incidents, got %d", len(created))
	}
	for _, inc := range created {
		peer := inc.Events[0].Attrs["peer"]
		t.Run(peer, func(t *testing.T) {
			// These are the fields rendered in the card and the email body;
			// deliberately do not count a hidden group key or in-memory Events.
			visible := strings.Join([]string{inc.Summary(), inc.ActorName, inc.Node, strings.Join(inc.Chain, "\n")}, "\n")
			if !strings.Contains(visible, peer) {
				t.Fatalf("clock-skew incident hides affected peer %q (group_key=%q); operator-visible alert:\n%s", peer, inc.GroupKey, visible)
			}
		})
	}
}
