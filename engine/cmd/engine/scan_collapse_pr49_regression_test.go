package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

func pr49NGFW(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var blocks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/block" {
			blocks.Add(1)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &blocks
}

func pr49PersistedIncident(t *testing.T, inc *incidents.Incident) incidents.Incident {
	t.Helper()
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	var restored incidents.Incident
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	return restored
}

// Use the three shipped rules, their real thresholds and their normal file
// order. The same 60 SSH SYNs also satisfy the 20-destination host sweep.
func TestPR49HammerCannotSuppressSweepResponse(t *testing.T) {
	files := map[string]string{}
	for _, name := range []string{"net-inbound-portscan.yml", "net-inbound-service-hammer.yml", "net-inbound-sweep.yml"} {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(raw)
	}
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const ip = "203.0.113.7"
	var events []*model.Event
	for i := 0; i < 60; i++ {
		ev := flow(model.FormatTS(now.Add(-5*time.Minute+time.Duration(i)*time.Second)), ip, 22)
		ev.DstIP = fmt.Sprintf("192.0.2.%d", i%20+1)
		ev.Attrs["syn_only"] = "1"
		events = append(events, ev)
	}
	dets, _ := eval.Evaluate(eval.Input{Rules: e.current(), Events: events, Now: now})
	if len(dets) != 2 || dets[0].Rule.ID != "a41c-net-072" || dets[1].Rule.ID != "a41c-net-071" {
		t.Fatalf("fixture must trigger hammer followed by sweep: %+v", dets)
	}
	created, _, _ := e.reg.Apply(dets, now)
	if len(created) != 1 {
		t.Fatalf("want one subnet incident, got %d", len(created))
	}
	inc := created[0]
	if inc.RuleID != "a41c-net-071" || inc.Level != "medium" || !slices.Contains(inc.MemberRules(ip), "a41c-net-071") {
		t.Errorf("sweep disappeared: representative=%s level=%s member_rules=%v", inc.RuleID, inc.Level, inc.MemberRules(ip))
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 1 {
		t.Errorf("host sweep must block its source once; got %d blocks, response_log=%v", blocks.Load(), f.rows("response_log"))
	}
}

// A fresh engine must preserve the 32 successful blocks still inside the
// incident's one-hour budget, while permitting genuinely new member IPs.
func TestPR49IncidentCapSurvivesRestart(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 32; i++ {
		events = append(events, portScan(fmt.Sprintf("203.0.113.%d", i), 3)...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one /24 incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 32 {
		t.Fatalf("pre-restart blocks=%d, want 32", blocks.Load())
	}
	restored := pr49PersistedIncident(t, created[0])
	// Keep the same persisted response_log, but discard all process memory.
	f.mu.Lock()
	f.selects["FROM response_log"] = strings.Join(f.inserts["response_log"], "\n") + "\n"
	f.mu.Unlock()
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{restored})
	restarted.restoreRespState([]incidents.Incident{restored}, now.Add(time.Minute))
	created, updated := restarted.applyEvents(portScan("203.0.113.33", 3), now.Add(time.Minute))
	if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != restored.IncidentID {
		t.Fatal("new member must join the restored incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
	if blocks.Load() != 32 {
		t.Fatalf("restart bypassed block_cap=32/1h: %d successful blocks in one incident within a minute", blocks.Load())
	}
}

// Membership alone is not evidence of a response. Before restart B only
// matched a rule without respond; a later scan by B must still be handled.
func TestPR49RestartDoesNotMarkUnansweredMemberDone(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const scanner, hammerOnly = "203.0.113.10", "203.0.113.20"
	created, _ := e.applyEvents(append(portScan(scanner, 3), hammer(hammerOnly, 3)...), now)
	if len(created) != 1 || len(created[0].Members) != 2 {
		t.Fatal("fixture must contain the scanner and the hammer-only member")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 1 || e.respStatus(created[0].IncidentID+"|"+hammerOnly) != "" {
		t.Fatal("only the scanner should have a response before restart")
	}
	restored := pr49PersistedIncident(t, created[0])
	f.mu.Lock()
	f.selects["FROM response_log"] = strings.Join(f.inserts["response_log"], "\n") + "\n"
	f.mu.Unlock()
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{restored})
	restarted.restoreRespState([]incidents.Incident{restored}, now.Add(time.Minute))
	newScan := portScan(hammerOnly, 3)
	for i, ev := range newScan {
		ev.TS = model.FormatTS(now.Add(time.Minute + time.Duration(i)*time.Second))
	}
	_, updated := restarted.applyEvents(newScan, now.Add(2*time.Minute))
	if len(updated) != 1 || !slices.Contains(updated[0].MemberRules(hammerOnly), "t-scan") {
		t.Fatal("fixture must now have a scan detection for the previously unanswered member")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Minute))
	if blocks.Load() != 2 {
		t.Fatalf("restart turned unanswered member into %q; later scan was not blocked (blocks=%d)",
			restarted.respStatus(restored.IncidentID+"|"+hammerOnly), blocks.Load())
	}
}

// Rule IDs in an open incident are historical. Removing one rule through
// the supported reload path must not panic in the response goroutine.
func TestPR49RemovedMemberRuleDoesNotPanic(t *testing.T) {
	f := newFakeCH(t)
	srv, _ := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	created, _ := e.applyEvents(append(portScan("203.0.113.10", 3), hammer("203.0.113.20", 3)...), now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	if err := os.Remove(filepath.Join(e.rulesDir, "hammer.yml")); err != nil {
		t.Fatal(err)
	}
	e.maybeReload(true)
	if e.ruleFor("t-hammer") != nil {
		t.Fatal("fixture rule was not removed by reload")
	}
	_, updated := e.applyEvents(portScan("203.0.113.30", 3), now.Add(time.Minute))
	if len(updated) != 1 {
		t.Fatal("new member must update the existing incident")
	}
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("autoRespond panicked on a removed member rule: %v (an unhandled goroutine panic terminates the engine)", p)
		}
	}()
	e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
}

// The first executor outage queues 33 retries and returns all reservations.
// Recovery must not execute all 33 through expireBlocks outside block_cap.
// The production responder has a real one-minute backoff and no public clock
// injection, so this integration regression waits for that first retry only.
func TestPR49RetriesRespectIncidentCap(t *testing.T) {
	if testing.Short() {
		t.Skip("exercises the real one-minute responder retry backoff")
	}
	var recovered atomic.Bool
	var successful atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/block" {
			t.Errorf("unexpected executor path %q", req.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !recovered.Load() {
			http.Error(w, "fixture executor unavailable", http.StatusServiceUnavailable)
			return
		}
		successful.Add(1)
	}))
	t.Cleanup(srv.Close)
	f := newFakeCH(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Now()
	var events []*model.Event
	for i := 1; i <= 33; i++ {
		events = append(events, portScan(fmt.Sprintf("203.0.113.%d", i), 3)...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one /24 incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if successful.Load() != 0 || len(e.resp.Active()) != 0 {
		t.Fatal("all first attempts must fail")
	}
	recovered.Store(true)
	// Split the real wait into two bounded sleeps; no deployed service is used.
	time.Sleep(31 * time.Second)
	time.Sleep(30 * time.Second)
	e.expireBlocks(context.Background(), time.Now())
	if got := successful.Load(); got == 0 {
		t.Fatal("fixture did not reach the retry path")
	} else if got > 32 {
		t.Fatalf("retry bypassed block_cap=32/1h: %d successful blocks, cap ledger=%d", got, len(e.respCap[created[0].IncidentID]))
	}
}
