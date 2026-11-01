package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// Evaluate can return two windows for the same rule and source in one poll
// (for example, a backlog after startup). With different exporter nodes the
// ordinary registry keeps both incidents. The collapsed registry must retain
// the trusted window for response even if a later window from an untrusted
// exporter overwrites the same rule|IP part before snapshotIncidents runs.
func TestPR49Round7LaterUntrustedWindowCannotEraseTrustedScan(t *testing.T) {
	for _, collapsed := range []bool{false, true} {
		t.Run(fmt.Sprintf("collapse_%t", collapsed), func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			files := pr49FollowupRules(t, "net-inbound-portscan.yml")
			if !collapsed {
				files["net-inbound-portscan.yml"] = strings.Replace(files["net-inbound-portscan.yml"],
					"collapse:\n  by: src.net\n  group: inbound-scan\n", "", 1)
			}
			e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			const scanner = "203.0.113.7"
			trusted := pr49Round3Scan(scanner, 50, now.Add(-14*time.Minute))
			untrusted := pr49Round3Scan(scanner, 50, now.Add(-time.Minute))
			for _, ev := range untrusted {
				ev.Node = "198.51.100.9"
				ev.Attrs["transport"] = "udp"
				ev.Attrs["peer"] = "198.51.100.9:2055"
			}
			events := append(trusted, untrusted...)
			for _, ev := range events {
				ev.ReceivedAt = now // one freshly received batch, retained by the engine
			}
			dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
			if len(dets) != 2 || dets[0].Key != scanner || dets[1].Key != scanner {
				t.Fatalf("fixture must produce two real detection windows for one source: detections=%d", len(dets))
			}
			firstTrusted, _, _ := e.splitTrusted(dets[0].Events)
			secondTrusted, _, _ := e.splitTrusted(dets[1].Events)
			if len(firstTrusted) != 50 || len(secondTrusted) != 0 || dets[0].Events[0].Node == dets[1].Events[0].Node {
				t.Fatal("fixture must have a trusted scan followed by a separate untrusted exporter window")
			}
			created, updated, _ := e.reg.Apply(dets, now)
			wantCreated := 2
			if collapsed {
				wantCreated = 1
			}
			if len(created) != wantCreated {
				t.Fatalf("unexpected registry path: created=%d, want %d", len(created), wantCreated)
			}
			e.autoRespond(context.Background(), snapshotIncidents(append(created, updated...)), now)
			if got := blocks.Load(); got != 1 {
				t.Fatalf("later untrusted window erased an independently qualifying trusted scan: blocks=%d response_log=%v",
					got, f.rows("response_log"))
			}
			if active := e.resp.Active(); len(active) != 1 || active[0].IP != scanner {
				t.Fatalf("only the trusted scan source may be blocked, got %+v", active)
			}
		})
	}
}

// POST /ingest/events accepts src_ip as a string, and emitHTTPBatch marks the
// events as trusted without trimming that field. The ordinary response path
// trims targets in Rule.RespondTargets. Enabling collapse must preserve that
// behavior: NetKey already accepts whitespace around the address.
func TestPR49Round7CollapsedTargetsPreserveOrdinaryTrimming(t *testing.T) {
	for _, source := range []string{"203.0.113.7", " 203.0.113.7 ", "\t2001:db8:1::7\t"} {
		for _, collapsed := range []bool{false, true} {
			t.Run(fmt.Sprintf("source_%q/collapse_%t", source, collapsed), func(t *testing.T) {
				f := newFakeCH(t)
				srv, blocks := pr49NGFW(t)
				files := pr49FollowupRules(t, "net-inbound-portscan.yml")
				if !collapsed {
					files["net-inbound-portscan.yml"] = strings.Replace(files["net-inbound-portscan.yml"],
						"collapse:\n  by: src.net\n  group: inbound-scan\n", "", 1)
				}
				e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
				now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
				events := pr49Round3Scan(source, 50, now.Add(-time.Minute))
				for _, ev := range events {
					ev.Attrs["transport"] = "http"
				}
				wantIP := strings.TrimSpace(source)
				r := e.ruleFor("a41c-net-070")
				if r == nil || r.Collapsed() != collapsed {
					t.Fatal("fixture must load the requested collapse setting")
				}
				if targets, _ := r.RespondTargets(events); len(targets) != 1 || targets[0] != wantIP {
					t.Fatalf("ordinary response must accept this source: targets=%v", targets)
				}
				created, updated := e.applyEvents(events, now)
				if len(created) != 1 || len(updated) != 0 || (created[0].Collapsed == 1) != collapsed {
					t.Fatalf("want one incident on the requested path: created=%d updated=%d", len(created), len(updated))
				}
				e.autoRespond(context.Background(), snapshotIncidents(created), now)
				if got := blocks.Load(); got != 1 {
					t.Fatalf("source %q must block %s once, including with collapse: blocks=%d response_log=%v",
						source, wantIP, got, f.rows("response_log"))
				}
				if active := e.resp.Active(); len(active) != 1 || active[0].IP != wantIP {
					t.Fatalf("wrong response target: want %s, got %+v", wantIP, active)
				}
			})
		}
	}
}

// The responder canonicalizes IPv6 before executing and journaling a block.
// Prepared HTTP events retain their original IPv6 spelling. Once that member
// is evicted, restart has only the journal's canonical IP for deduplication;
// returning under the same original spelling must not repeat the block.
func TestPR49Round7EvictedIPv6SpellingMustNotRepeatBlockAfterRestart(t *testing.T) {
	const canonical = "2001:db8:1::7"
	for _, source := range []string{canonical, "2001:0DB8:0001:0000:0000:0000:0000:0007"} {
		t.Run(source, func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			files := pr49FollowupRules(t, "net-inbound-portscan.yml", "net-inbound-service-hammer.yml")
			e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			scan := func(at time.Time) []*model.Event {
				events := pr49Round3Scan(source, 50, at)
				for _, ev := range events {
					ev.Attrs["transport"] = "http"
				}
				return events
			}
			created, _ := e.applyEvents(scan(now.Add(-time.Minute)), now)
			if len(created) != 1 || created[0].Collapsed != 1 {
				t.Fatal("fixture must create one collapsed incident")
			}
			inc := created[0]
			e.autoRespond(context.Background(), snapshotIncidents(created), now)
			if blocks.Load() != 1 || blockedIPs(f.rows("response_log"))[canonical] != 1 {
				t.Fatal("fixture must execute and journal one block using the canonical IPv6 address")
			}

			_, updated := e.applyEvents(pr49Round6HammerNeighbors(now.Add(time.Second)), now.Add(time.Minute))
			if len(updated) != 1 || updated[0].IncidentID != inc.IncidentID || len(updated[0].Members) != 256 {
				t.Fatal("neighbors must fill the same incident's member limit")
			}
			for _, member := range updated[0].Members {
				if member.IP == source || member.IP == canonical {
					t.Fatal("fixture must evict the scanner from persisted members")
				}
			}
			e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
			if blocks.Load() != 1 {
				t.Fatal("hammer-only neighbors must not cause more blocks")
			}
			restored := pr49PersistedIncident(t, updated[0])
			pr49FollowupSaveResponses(f)
			restarted := testEngine(t, f, e.rulesDir, ipsConfig(srv), "fixture", "fixture")
			restarted.reg = incidents.NewRegistry(100, []incidents.Incident{restored})
			restarted.restoreRespState([]incidents.Incident{restored}, now.Add(2*time.Minute))
			if restarted.respStatus(inc.IncidentID+"|"+canonical) != "done" {
				t.Fatal("fixture must restore the journal decision well inside respStateTTL")
			}

			created, updated = restarted.applyEvents(scan(now.Add(2*time.Minute)), now.Add(3*time.Minute))
			if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != inc.IncidentID {
				t.Fatal("returning source must update its original open incident")
			}
			restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(3*time.Minute))
			if got := blocks.Load(); got != 1 {
				t.Fatalf("same incident and IPv6 address blocked again after eviction/restart: source=%q journal_ip=%q blocks=%d",
					source, canonical, got)
			}
		})
	}
}
