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

// User-Agent is copied into attrs.user_agent by the WAF normalizer. A valid
// ordinary rule can group by that field: its value must not select the
// collapsed response path. The same rule and events block on main.
func TestPR49Round6OrdinaryGroupPrefixCannotSuppressResponse(t *testing.T) {
	for _, agent := range []string{"scanner/1", "collapse:scanner/1", "collapse:inbound-scan:203.0.113.0/24"} {
		t.Run(agent, func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			yml := strings.Replace(respondRule, "detection:\n", "detection:\n  group_by: attrs.user_agent\n", 1)
			e := testEngine(t, f, rulesDirWith(t, map[string]string{"waf.yml": yml}), ipsConfig(srv), "fixture", "fixture")
			if e.ruleFor("t-waf").Collapse != nil {
				t.Fatal("fixture must use an ordinary rule")
			}
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			const ip = "203.0.113.9"
			events := []*model.Event{
				wafEvent(model.FormatTS(now.Add(-2*time.Second)), ip, "file", ""),
				wafEvent(model.FormatTS(now.Add(-time.Second)), ip, "file", ""),
			}
			for _, ev := range events {
				ev.Attrs["user_agent"] = agent
			}
			created, updated := e.applyEvents(events, now)
			if len(created) != 1 || len(updated) != 0 || created[0].EventCount != 2 {
				t.Fatalf("want one ordinary two-event detection: created=%d updated=%d", len(created), len(updated))
			}
			inc := created[0]
			e.autoRespond(context.Background(), snapshotIncidents(created), now)
			if got := blocks.Load(); got != 1 {
				t.Errorf("ordinary WAF incident lost its block for user_agent=%q: blocks=%d group_key=%q state=%q",
					agent, got, inc.GroupKey, e.respStatus(inc.IncidentID))
			}
			if active := e.resp.Active(); len(active) != 1 || active[0].IP != ip {
				t.Errorf("ordinary response must target %s, got %+v", ip, active)
			}

			// Restart must restore the same incident-level decision as main.
			restored := pr49PersistedIncident(t, inc)
			restarted := testEngine(t, f, e.rulesDir, ipsConfig(srv), "fixture", "fixture")
			if n := restarted.restoreRespState([]incidents.Incident{restored}, now); n != 1 || restarted.respStatus(inc.IncidentID) != "done" {
				t.Errorf("ordinary incident was not restored as done: restored=%d state=%q", n, restarted.respStatus(inc.IncidentID))
			}
		})
	}
}

// NetFlow/IPFIX records may omit the source address. The decoder returns an
// empty SrcIP for a template without sourceIPv4Address/sourceIPv6Address;
// prepared events delivered by an HTTP integration are trusted too. eval's
// fallback grouping key is then Node, not an observed source address.
func TestPR49Round6MissingSourceMustNotBlockExporter(t *testing.T) {
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
			if r := e.ruleFor("a41c-net-070"); r == nil || r.Collapsed() != collapsed {
				t.Fatal("fixture collapse setting was not loaded")
			}
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			const exporter = "203.0.113.9"
			events := pr49Round3Scan("", 50, now.Add(-time.Minute))
			for _, ev := range events {
				ev.Node = exporter
				ev.DstIP = "192.168.0.10"
				ev.Attrs["transport"] = "http"
			}
			dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
			if len(dets) != 1 || dets[0].Key != exporter {
				t.Fatal("fixture must reach the real empty-src.ip grouping fallback")
			}
			if targets, _ := dets[0].Rule.RespondTargets(dets[0].Events); len(targets) != 0 {
				t.Fatalf("no trusted event contains a source address: targets=%v", targets)
			}
			created, updated, _ := e.reg.Apply(dets, now)
			e.autoRespond(context.Background(), snapshotIncidents(append(created, updated...)), now)
			if got := blocks.Load(); got != 0 {
				t.Fatalf("missing src.ip caused %d block(s) of the exporter: active=%+v", got, e.resp.Active())
			}
		})
	}
}

// The non-responding hammer rule shares the scan's /48 incident. These flows
// can come from an untrusted UDP exporter: they must not evict the trusted
// scan from the response decision merely by filling the 256 display slots.
func pr49Round6HammerNeighbors(at time.Time) []*model.Event {
	var events []*model.Event
	for i := 1; i <= 256; i++ {
		ip := fmt.Sprintf("2001:db8:1:%x::1", i)
		for j := 0; j < 60; j++ {
			ev := flow(model.FormatTS(at.Add(time.Duration(i+j)*time.Millisecond)), ip, 22)
			ev.Attrs["syn_only"] = "1"
			ev.Attrs["transport"] = "udp"
			events = append(events, ev)
		}
	}
	return events
}

func TestPR49Round6MemberLimitCannotSuppressTrustedScan(t *testing.T) {
	for _, collapsed := range []bool{false, true} {
		t.Run(fmt.Sprintf("collapse_%t", collapsed), func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			files := pr49FollowupRules(t, "net-inbound-portscan.yml", "net-inbound-service-hammer.yml")
			if !collapsed {
				for name, yml := range files {
					files[name] = strings.Replace(yml, "collapse:\n  by: src.net\n  group: inbound-scan\n", "", 1)
				}
			}
			e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
			e.reg.SetMaxNew(200) // production default; the scan rule is evaluated first
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			const scanner = "2001:db8:1::7"
			events := append(pr49Round3Scan(scanner, 50, now.Add(-2*time.Minute)), pr49Round6HammerNeighbors(now.Add(-time.Minute))...)
			dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
			if len(dets) != 257 || dets[0].Rule.ID != "a41c-net-070" || dets[0].Key != scanner {
				t.Fatal("fixture must evaluate one trusted scan before 256 non-responding neighbors")
			}
			created, updated, _ := e.reg.Apply(dets, now)
			if collapsed && len(created) != 1 {
				t.Fatalf("want one /48 incident, got %d", len(created))
			}
			e.autoRespond(context.Background(), snapshotIncidents(append(created, updated...)), now)
			if got := blocks.Load(); got != 1 {
				t.Fatalf("trusted scanner must be blocked once despite newer untrusted neighbors: blocks=%d", got)
			}
			if active := e.resp.Active(); len(active) != 1 || active[0].IP != scanner {
				t.Fatalf("only the trusted scanner may be blocked, got %+v", active)
			}
		})
	}
}

// The last persisted members list drops old addresses. Restarting creates a
// fresh responder with no active-IP cache, so that list alone cannot preserve
// the decision for an already blocked address that subsequently returns.
func TestPR49Round6EvictedMemberMustNotBlockAgainAfterRestart(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	files := pr49FollowupRules(t, "net-inbound-portscan.yml", "net-inbound-service-hammer.yml")
	e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const scanner = "2001:db8:1::7"
	created, _ := e.applyEvents(pr49Round3Scan(scanner, 50, now.Add(-time.Minute)), now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	inc := created[0]
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 1 || e.respStatus(inc.IncidentID+"|"+scanner) != "done" {
		t.Fatal("fixture must block the scanner before eviction")
	}
	_, updated := e.applyEvents(pr49Round6HammerNeighbors(now.Add(time.Second)), now.Add(time.Minute))
	if len(updated) != 1 || updated[0].IncidentID != inc.IncidentID {
		t.Fatal("neighbors must update the same still-open subnet incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
	if blocks.Load() != 1 {
		t.Fatal("non-responding neighbors must not cause additional blocks")
	}
	restored := pr49PersistedIncident(t, updated[0])
	pr49FollowupSaveResponses(f)
	restarted := testEngine(t, f, e.rulesDir, ipsConfig(srv), "fixture", "fixture")
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{restored})
	restarted.restoreRespState([]incidents.Incident{restored}, now.Add(2*time.Minute))
	created, updated = restarted.applyEvents(pr49Round3Scan(scanner, 50, now.Add(2*time.Minute)), now.Add(3*time.Minute))
	if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != inc.IncidentID {
		t.Fatal("returning scanner must update its original open incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(3*time.Minute))
	if got := blocks.Load(); got != 1 {
		t.Fatalf("same incident/IP was blocked again after member eviction and restart: blocks=%d state=%q",
			got, restarted.respStatus(inc.IncidentID+"|"+scanner))
	}
}
