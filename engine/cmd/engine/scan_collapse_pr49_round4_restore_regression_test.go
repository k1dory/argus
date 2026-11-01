package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// The first attempt fails and is journaled. After a restart the next attempt
// succeeds, but only its reserve reaches ClickHouse. The old failure must not
// turn that newer, unresolved reserve into permission to block a third time.
func TestPR49Round4OlderFailureCannotClearLaterReserve(t *testing.T) {
	f := newFakeCH(t)
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
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const ip = "203.0.113.7"
	e := scanEngine(t, f, 1, ipsConfig(srv))
	created, _ := e.applyEvents(pr49Round3Scan(ip, 3, now.Add(-time.Second)), now)
	if len(created) != 1 {
		t.Fatal("fixture must create one collapsed incident")
	}
	e.autoRespond(ctx, snapshotIncidents(created), now)
	if blocks.Load() != 0 || e.resp.Pending() != 1 || len(f.rows("response_log")) != 3 {
		t.Fatal("fixture requires a reserve, an executor failure and a retry notice")
	}
	old := pr49PersistedIncident(t, created[0])
	pr49FollowupSaveResponses(f)

	second := scanEngine(t, f, 1, ipsConfig(srv))
	second.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	second.restoreRespState([]incidents.Incident{old}, now.Add(time.Minute))
	available.Store(true)
	f.mu.Lock()
	f.failIf = func(table, body string) bool {
		return table == "response_log" && !strings.Contains(body, `"detail":"резерв:`)
	}
	f.mu.Unlock()
	_, updated := second.applyEvents(pr49Round3Scan(ip, 4, now.Add(time.Minute)), now.Add(time.Minute+time.Second))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("the fresh scan must update the restored incident")
	}
	second.autoRespond(ctx, snapshotIncidents(updated), now.Add(time.Minute+time.Second))
	if blocks.Load() != 1 || len(f.rows("response_log")) != 4 {
		t.Fatal("fixture requires one actual block and only its new reserve in the journal")
	}
	old = pr49PersistedIncident(t, updated[0])
	f.mu.Lock()
	f.failIf = nil
	f.mu.Unlock()
	pr49FollowupSaveResponses(f)

	third := scanEngine(t, f, 1, ipsConfig(srv))
	third.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	third.restoreRespState([]incidents.Incident{old}, now.Add(2*time.Minute))
	state := third.respStatus(old.IncidentID + "|" + ip)
	_, updated = third.applyEvents(pr49Round3Scan(ip, 5, now.Add(2*time.Minute)), now.Add(2*time.Minute+time.Second))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("the third scan must still belong to the same incident")
	}
	third.autoRespond(ctx, snapshotIncidents(updated), now.Add(2*time.Minute+time.Second))
	if state != "done" || blocks.Load() != 1 {
		t.Fatalf("a later reserve without outcome must be done despite an older failure: restored state=%q, actual blocks=%d, want 1", state, blocks.Load())
	}
}

// A failed reservation can age out of the rolling window. A later attempt then
// acquires a new slot and succeeds. A restart must preserve that current slot,
// instead of restoring the earliest (already expired) timestamp for the IP.
func TestPR49Round4RestartKeepsRenewedCapSlot(t *testing.T) {
	f := newFakeCH(t)
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
	ctx := context.Background()
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	const firstIP = "203.0.113.7"
	e := scanEngine(t, f, 1, ipsConfig(srv))
	created, _ := e.applyEvents(pr49Round3Scan(firstIP, 3, now.Add(-time.Second)), now)
	if len(created) != 1 {
		t.Fatal("fixture must create one collapsed incident")
	}
	e.autoRespond(ctx, snapshotIncidents(created), now)
	if blocks.Load() != 0 || e.resp.Pending() != 1 || len(f.rows("response_log")) != 3 {
		t.Fatal("fixture requires a fully journaled failed first attempt")
	}
	old := pr49PersistedIncident(t, created[0])
	pr49FollowupSaveResponses(f)

	// Still inside auto_close=2h, but the old block_cap_window=1h has elapsed.
	retryAt := now.Add(61 * time.Minute)
	second := scanEngine(t, f, 1, ipsConfig(srv))
	second.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	second.restoreRespState([]incidents.Incident{old}, retryAt)
	available.Store(true)
	_, updated := second.applyEvents(pr49Round3Scan(firstIP, 4, retryAt.Add(-time.Second)), retryAt)
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("retry must update the still-open incident")
	}
	second.autoRespond(ctx, snapshotIncidents(updated), retryAt)
	if blocks.Load() != 1 || len(second.respCap[old.IncidentID]) != 1 || !second.respCapIP[old.IncidentID][firstIP].Equal(retryAt) {
		t.Fatal("fixture requires one successful block with a newly acquired, current-window slot")
	}
	old = pr49PersistedIncident(t, updated[0])
	pr49FollowupSaveResponses(f)

	restartAt := retryAt.Add(time.Minute)
	third := scanEngine(t, f, 1, ipsConfig(srv))
	third.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	third.restoreRespState([]incidents.Incident{old}, restartAt)
	restoredAt := third.respCapIP[old.IncidentID][firstIP]
	_, updated = third.applyEvents(pr49Round3Scan("203.0.113.8", 3, restartAt.Add(-time.Second)), restartAt)
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("the second address must join the same incident")
	}
	third.autoRespond(ctx, snapshotIncidents(updated), restartAt)
	if got := blocks.Load(); got != 1 {
		t.Fatalf("restart discarded a current cap slot: actual blocks=%d within one minute with block_cap=1/1h; slot restored at %s instead of %s", got, restoredAt, retryAt)
	}
}
