package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func pr49Round3Scan(ip string, n int, at time.Time) []*model.Event {
	events := make([]*model.Event, 0, n)
	for i := 0; i < n; i++ {
		ev := flow(model.FormatTS(at.Add(time.Duration(i)*time.Millisecond)), ip, uint16(1000+i))
		ev.Attrs["syn_only"] = "1"
		events = append(events, ev)
	}
	return events
}

// The shipped port-scan rule has enough trusted evidence on its own. Adding
// later UDP events from an untrusted exporter must not remove that evidence
// from the response decision when aggregate trims its display/event budget.
func TestPR49Round3BudgetDoesNotDiscardTrustedEvidence(t *testing.T) {
	for _, extra := range []int{0, 2000} {
		t.Run(fmt.Sprintf("later_untrusted_events_%d", extra), func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			e := testEngine(t, f, rulesDirWith(t, pr49FollowupRules(t, "net-inbound-portscan.yml")), ipsConfig(srv), "fixture", "fixture")
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			const ip = "203.0.113.7"
			events := pr49Round3Scan(ip, 50+extra, now.Add(-3*time.Second))
			for i, ev := range events {
				ev.Attrs["transport"] = "udp"
				ev.Attrs["peer"] = "10.0.10.9" // configured trusted_sources
				if i >= 50 {
					ev.Attrs["peer"] = "198.51.100.9"
				}
			}
			trusted, _, _ := e.splitTrusted(events)
			if len(trusted) != 50 {
				t.Fatalf("fixture requires 50 trusted flows, got %d", len(trusted))
			}
			created, _ := e.applyEvents(events, now)
			if len(created) != 1 || created[0].EventCount != uint32(len(events)) {
				t.Fatalf("fixture must detect the complete scan: %+v", created)
			}
			e.autoRespond(context.Background(), snapshotIncidents(created), now)
			if got := blocks.Load(); got != 1 {
				t.Fatalf("50 trusted scan flows must trigger one block even with %d later untrusted flows: blocks=%d, retained=%d, state=%q",
					extra, got, len(created[0].Events), e.respStatus(created[0].IncidentID+"|"+ip))
			}
		})
	}
}

// A min_events value below both the detection count and the global event
// budget is valid. Four samples per part must not replace its actual trusted
// count: all 32 sources qualify and fit exactly into the 32-address cap.
func TestPR49Round3BudgetPreservesPerAddressMinEvents(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	files := pr49FollowupRules(t, "net-inbound-portscan.yml")
	files["net-inbound-portscan.yml"] = strings.Replace(files["net-inbound-portscan.yml"], "  ttl: 12h", "  ttl: 12h\n  min_events: 8", 1)
	e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
	if r := e.ruleFor("a41c-net-070"); r == nil || r.RespondMinEvents() != 8 {
		t.Fatal("fixture must load min_events=8")
	}
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 32; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("203.0.113.%d", i), 80, now.Add(-time.Minute+time.Duration(i)*time.Second))...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 || len(created[0].Members) != 32 {
		t.Fatal("fixture must produce one incident with 32 qualifying sources")
	}
	for _, m := range created[0].Members {
		if m.Events != 80 {
			t.Fatalf("fixture member lost its detection count: %+v", m)
		}
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if got := blocks.Load(); got != 32 {
		t.Fatalf("all 32 sources have 80 trusted events but only %d blocked after retaining %d/2560 events",
			got, len(created[0].Events))
	}
}
