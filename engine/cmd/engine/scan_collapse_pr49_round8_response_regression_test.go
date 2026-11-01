package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// Sliding windows from Evaluate can contain the same event. Summing their
// origins must not turn one trusted observation into the two observations
// required by respond.min_events, even when untrusted traffic fires both
// windows. The ordinary response path keeps waiting on this exact input.
func TestPR49Round8OverlappingWindowsMustNotMultiplyTrustedEvents(t *testing.T) {
	for _, collapsed := range []bool{false, true} {
		t.Run(fmt.Sprintf("collapse_%t", collapsed), func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			files := pr49FollowupRules(t, "net-inbound-portscan.yml")
			files["net-inbound-portscan.yml"] = strings.Replace(files["net-inbound-portscan.yml"],
				"  ttl: 12h", "  ttl: 12h\n  min_events: 2", 1)
			if !collapsed {
				files["net-inbound-portscan.yml"] = strings.Replace(files["net-inbound-portscan.yml"],
					"collapse:\n  by: src.net\n  group: inbound-scan\n", "", 1)
			}
			e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
			r := e.ruleFor("a41c-net-070")
			if r == nil || r.Collapsed() != collapsed || r.RespondMinEvents() != 2 {
				t.Fatal("fixture must use the requested collapse setting and min_events=2")
			}
			start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
			now := start.Add(11 * time.Minute)
			const victim = "203.0.113.7"
			events := pr49Round3Scan(victim, 51, start)
			for i, ev := range events {
				ev.TS = model.FormatTS(start.Add(time.Duration(i) * time.Second))
				ev.ReceivedAt = now // a freshly received backlog can span several windows
				ev.Attrs["transport"] = "udp"
				ev.Attrs["peer"] = "198.51.100.9:2055"
			}
			// At 10m+1s only event zero expires; the other 49 events occur in
			// both detections. Just one of those shared events is trusted.
			events[50].TS = model.FormatTS(start.Add(10*time.Minute + time.Second))
			events[25].Attrs["transport"] = "http"
			trusted, _, _ := e.splitTrusted(events)
			if len(trusted) != 1 {
				t.Fatalf("fixture must have exactly one trusted input event, got %d", len(trusted))
			}
			dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
			if len(dets) != 2 {
				t.Fatalf("fixture must produce two real sliding windows, got %d", len(dets))
			}
			for i, d := range dets {
				windowTrusted, _, _ := e.splitTrusted(d.Events)
				if d.Key != victim || len(d.Events) != 50 || len(windowTrusted) != 1 || windowTrusted[0] != trusted[0] {
					t.Fatalf("window %d must contain 50 events and the same single trusted event", i)
				}
			}
			created, updated, _ := e.reg.Apply(dets, now)
			if len(created) != 1 || (created[0].Collapsed == 1) != collapsed {
				t.Fatal("fixture must create one incident on the requested path")
			}
			e.autoRespond(context.Background(), snapshotIncidents(append(created, updated...)), now)
			if got := blocks.Load(); got != 0 {
				t.Fatalf("one trusted event was counted twice across overlapping windows and blocked %s with min_events=2: blocks=%d response_log=%v",
					victim, got, f.rows("response_log"))
			}
			if active := e.resp.Active(); len(active) != 0 {
				t.Fatalf("insufficient trusted evidence must not create an active block: %+v", active)
			}
		})
	}
}

// Evaluate groups by the raw src.ip spelling. After collapse canonicalizes
// those keys, a larger untrusted detection must not make an independent
// trusted detection look like an unchanged replay of the same part. The
// trusted spelling is accepted by POST /ingest/events and by ordinary IPS.
func TestPR49Round8CanonicalAliasesMustNotSuppressTrustedScan(t *testing.T) {
	for _, tc := range []struct {
		name, canonical, trustedSource string
	}{
		{"ipv4_mapped", "203.0.113.7", "::ffff:203.0.113.7"},
		{"ipv4_whitespace", "203.0.113.7", " 203.0.113.7 "},
		{"ipv6_expanded", "2001:db8:1::7", "2001:0DB8:0001:0000:0000:0000:0000:0007"},
	} {
		for _, collapsed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/collapse_%t", tc.name, collapsed), func(t *testing.T) {
				f := newFakeCH(t)
				srv, blocks := pr49NGFW(t)
				files := pr49FollowupRules(t, "net-inbound-portscan.yml")
				if !collapsed {
					files["net-inbound-portscan.yml"] = strings.Replace(files["net-inbound-portscan.yml"],
						"collapse:\n  by: src.net\n  group: inbound-scan\n", "", 1)
				}
				e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
				now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
				untrusted := pr49Round3Scan(tc.canonical, 51, now.Add(-2*time.Minute))
				for _, ev := range untrusted {
					ev.Node = "198.51.100.9"
					ev.Attrs["transport"] = "udp"
					ev.Attrs["peer"] = "198.51.100.9:2055"
				}
				// The UDP group fires first but ends after the trusted group,
				// so its final count and timestamp dominate the trusted scan.
				untrusted[50].TS = model.FormatTS(now.Add(-time.Second))
				trusted := pr49Round3Scan(tc.trustedSource, 50, now.Add(-time.Minute))
				for _, ev := range trusted {
					ev.Attrs["transport"] = "http"
				}
				events := append(untrusted, trusted...)
				for _, ev := range events {
					ev.ReceivedAt = now
				}
				dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
				if len(dets) != 2 || dets[0].Key != tc.canonical || dets[1].Key != tc.trustedSource ||
					len(dets[0].Events) != 51 || len(dets[1].Events) != 50 || !dets[0].Last.After(dets[1].Last) {
					t.Fatal("fixture must produce an untrusted detection before a smaller, earlier-ending trusted alias detection")
				}
				firstTrusted, _, _ := e.splitTrusted(dets[0].Events)
				secondTrusted, _, _ := e.splitTrusted(dets[1].Events)
				if len(firstTrusted) != 0 || len(secondTrusted) != 50 {
					t.Fatal("only the second detection may supply trusted evidence")
				}
				created, updated, _ := e.reg.Apply(dets, now)
				wantCreated := 2
				if collapsed {
					wantCreated = 1
				}
				if len(created) != wantCreated || (created[0].Collapsed == 1) != collapsed {
					t.Fatalf("unexpected registry path: created=%d, want %d", len(created), wantCreated)
				}
				e.autoRespond(context.Background(), snapshotIncidents(append(created, updated...)), now)
				if got := blocks.Load(); got != 1 {
					t.Fatalf("untrusted canonical spelling suppressed an independently qualifying trusted scan from %q: blocks=%d response_log=%v",
						tc.trustedSource, got, f.rows("response_log"))
				}
				if active := e.resp.Active(); len(active) != 1 || active[0].IP != tc.canonical {
					t.Fatalf("only the canonical source %s may be blocked: %+v", tc.canonical, active)
				}
			})
		}
	}
}
