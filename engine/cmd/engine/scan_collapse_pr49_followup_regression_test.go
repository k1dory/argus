package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

func pr49FollowupRules(t *testing.T, names ...string) map[string]string {
	t.Helper()
	files := make(map[string]string, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = string(raw)
	}
	return files
}

func pr49FollowupSaveResponses(f *fakeCH) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.selects["FROM response_log"] = strings.Join(f.inserts["response_log"], "\n") + "\n"
}

// A real shipped rule reaches its threshold at 50 ports, but evaluation
// returns the entire batch. Exceeding the incident's display/memory budget
// must not silently remove the only source address from autoRespond.
func TestPR49FollowupLargeScanStillBlocksSource(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := testEngine(t, f, rulesDirWith(t, pr49FollowupRules(t, "net-inbound-portscan.yml")), ipsConfig(srv), "fixture", "fixture")
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const ip = "203.0.113.7"
	var events []*model.Event
	for i := 0; i < 2001; i++ {
		ev := flow(model.FormatTS(now.Add(-3*time.Second+time.Duration(i)*time.Millisecond)), ip, uint16(1000+i))
		ev.Attrs["syn_only"] = "1"
		events = append(events, ev)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 || created[0].EventCount != 2001 || len(created[0].Members) != 1 {
		t.Fatalf("fixture must detect one 2001-event port scan: %+v", created)
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if got := blocks.Load(); got != 1 {
		t.Fatalf("qualifying scanner must be blocked once, got %d; retained events=%d, decision=%q, reservations=%d",
			got, len(created[0].Events), e.respStatus(created[0].IncidentID+"|"+ip), len(e.respCap[created[0].IncidentID]))
	}
}

// One source address consumes one reservation even when two independent
// executors both log success. A restart must not turn 16 addresses into an
// exhausted 32-address budget and suppress the next qualifying scanner.
func TestPR49FollowupRestoreCountsAddressesNotExecutors(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	cfg := ipsConfig(srv)
	second := cfg.HTTP[0]
	second.Name = "ngfw.second"
	cfg.HTTP = append(cfg.HTTP, second)
	e := scanEngine(t, f, 32, cfg)
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 16; i++ {
		events = append(events, portScan(fmt.Sprintf("203.0.113.%d", i), 3)...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 32 || len(e.respCap[created[0].IncidentID]) != 16 {
		t.Fatalf("fixture needs 16 reservations and 32 executor calls: reservations=%d calls=%d",
			len(e.respCap[created[0].IncidentID]), blocks.Load())
	}
	old := pr49PersistedIncident(t, created[0])
	pr49FollowupSaveResponses(f)
	restarted := scanEngine(t, f, 32, cfg)
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(time.Minute))
	_, updated := restarted.applyEvents(portScan("203.0.113.17", 3), now.Add(time.Minute))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("new address must join the restored incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
	if got := blocks.Load(); got != 34 {
		t.Fatalf("17th address must reach both executors, got %d total calls; restored reservations=%d, decision=%q",
			got, len(restarted.respCap[old.IncidentID]), restarted.respStatus(old.IncidentID+"|203.0.113.17"))
	}
}

// A failed attempt produces an executor failure AND an argus retry notice.
// The retry queue is not persisted. Restoring that notice as a final decision
// must not suppress this still-unblocked address after the executor recovers.
func TestPR49FollowupRestartRetriesFailedAddress(t *testing.T) {
	var available atomic.Bool
	var blocks atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/block" {
			http.Error(w, "unexpected fixture path", http.StatusNotFound)
			return
		}
		if !available.Load() {
			http.Error(w, "fixture executor unavailable", http.StatusServiceUnavailable)
			return
		}
		blocks.Add(1)
	}))
	t.Cleanup(srv.Close)
	f := newFakeCH(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const ip = "203.0.113.7"
	created, _ := e.applyEvents(portScan(ip, 3), now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 0 || len(f.rows("response_log")) != 2 || len(e.respCap[created[0].IncidentID]) != 1 {
		t.Fatal("fixture must log one failed executor attempt plus its queued-retry notice, retaining one slot")
	}
	old := pr49PersistedIncident(t, created[0])
	pr49FollowupSaveResponses(f)
	available.Store(true)
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(time.Second))
	_, updated := restarted.applyEvents(portScan(ip, 4), now.Add(2*time.Second))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("fresh scan activity must update the restored incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Second))
	if got := blocks.Load(); got != 1 {
		t.Fatalf("recovered executor must block the unanswered address, got %d blocks; decision=%q, reservations=%d",
			got, restarted.respStatus(old.IncidentID+"|"+ip), len(restarted.respCap[old.IncidentID]))
	}
}

// A rule can be removed while another shipped rule still owns the same
// collapse group. If the response journal then fails during startup, the
// documented fallback must exhaust the group budget even when the historical
// representative RuleID no longer resolves.
func TestPR49FollowupMissingRuleKeepsFailedRestoreClosed(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	files := pr49FollowupRules(t, "net-inbound-portscan.yml", "net-inbound-sweep.yml")
	e := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 32; i++ {
		for p := 0; p < 50; p++ {
			ev := flow(model.FormatTS(now.Add(-time.Second+time.Duration(p)*time.Millisecond)), fmt.Sprintf("203.0.113.%d", i), uint16(1000+p))
			ev.Attrs["syn_only"] = "1"
			events = append(events, ev)
		}
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 || created[0].RuleID != "a41c-net-070" {
		t.Fatal("fixture must create one incident represented by the port-scan rule")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 32 {
		t.Fatalf("fixture must exhaust the one-hour budget before restart: blocks=%d", blocks.Load())
	}
	old := pr49PersistedIncident(t, created[0])
	f.mu.Lock()
	f.selects["FROM response_log"] = "{\"exception\":\"Code: 159. DB::Exception: fixture response log unavailable\"}\n"
	f.mu.Unlock()
	delete(files, "net-inbound-portscan.yml")
	restarted := testEngine(t, f, rulesDirWith(t, files), ipsConfig(srv), "fixture", "fixture")
	if restarted.ruleFor(old.RuleID) != nil || restarted.ruleFor("a41c-net-071") == nil {
		t.Fatal("historical representative must be removed while host-sweep response remains configured")
	}
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(time.Minute))
	if restarted.respStatus(old.IncidentID+"|203.0.113.1") != "done" {
		t.Fatal("fixture must reach the journal-error fallback")
	}
	var sweep []*model.Event
	for i := 1; i <= 20; i++ {
		ev := flow(model.FormatTS(now.Add(time.Minute+time.Duration(i)*time.Millisecond)), "203.0.113.33", 9999)
		ev.DstIP = fmt.Sprintf("192.0.2.%d", i)
		ev.Attrs["syn_only"] = "1"
		sweep = append(sweep, ev)
	}
	_, updated := restarted.applyEvents(sweep, now.Add(2*time.Minute))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("host sweep must join the same restored subnet incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Minute))
	if got := blocks.Load(); got != 32 {
		t.Fatalf("missing representative bypassed block_cap=32/1h during failed restore: blocks=%d, reservations=%d",
			got, len(restarted.respCap[old.IncidentID]))
	}
}

// Incidents are persisted before autoRespond runs. If its response_log INSERT
// fails after successful firewall calls, a later successful empty SELECT is
// not evidence of an unused budget. The original addresses remain blocked.
func TestPR49FollowupLostResponseInsertDoesNotResetCap(t *testing.T) {
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
		t.Fatal("fixture must create one subnet incident")
	}
	// This is the incident row saved by cycle before it starts autoRespond.
	old := pr49PersistedIncident(t, created[0])
	f.mu.Lock()
	f.fail["response_log"] = true
	f.mu.Unlock()
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 32 || len(e.respCap[old.IncidentID]) != 32 || len(f.rows("response_log")) != 0 {
		t.Fatal("fixture must exhaust the cap at the firewall while response_log persistence fails")
	}
	f.mu.Lock()
	f.fail["response_log"] = false
	f.mu.Unlock()
	pr49FollowupSaveResponses(f)
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(time.Minute))
	_, updated := restarted.applyEvents(portScan("203.0.113.33", 3), now.Add(time.Minute))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("new address must join the restored incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
	if got := blocks.Load(); got != 32 {
		t.Fatalf("lost journal INSERT reset block_cap=32/1h: %d successful blocks within one minute, reservations=%d",
			got, len(restarted.respCap[old.IncidentID]))
	}
}
