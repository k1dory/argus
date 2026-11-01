package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// A restored failed attempt already owns a slot. Retrying that same address
// must reuse its slot, including when every slot was reserved before restart.
// The earlier follow-up test covers only one failure with 31 spare slots.
func TestPR49Round3RestartRetriesAtFullCap(t *testing.T) {
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
	var events []*model.Event
	for i := 1; i <= 32; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("203.0.113.%d", i), 3, now.Add(-time.Second))...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one subnet incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	// Запись вперёд: 32 резерва, 32 сбоя, 32 уведомления о повторе.
	if blocks.Load() != 0 || e.resp.Pending() != 32 || len(e.respCap[created[0].IncidentID]) != 32 || len(f.rows("response_log")) != 96 {
		t.Fatal("fixture requires 32 reserves, 32 failures, 32 retry notices, and 32 reserved slots")
	}
	old := pr49PersistedIncident(t, created[0])
	pr49FollowupSaveResponses(f)
	available.Store(true)
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(time.Minute))

	events = nil
	for i := 1; i <= 32; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("203.0.113.%d", i), 4, now.Add(2*time.Minute))...)
	}
	_, updated := restarted.applyEvents(events, now.Add(2*time.Minute+time.Second))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("fresh scans must update the restored incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Minute+time.Second))
	if got := blocks.Load(); got != 32 {
		t.Fatalf("recovered executor must block all 32 previously reserved addresses, got %d; reservations=%d, first state=%q",
			got, len(restarted.respCap[old.IncidentID]), restarted.respStatus(old.IncidentID+"|203.0.113.1"))
	}
	if got := len(restarted.respCap[old.IncidentID]); got != 32 {
		t.Fatalf("retries must reuse the 32 existing slots, got %d", got)
	}
}

// Members is a 256-address display/history sample. Successful journal rows
// for evicted addresses must still consume the incident's one-hour budget.
// Non-responding hammer detections evict the old scans without adding blocks.
func TestPR49Round3EvictedMembersStillConsumeRestoredCap(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 32; i++ {
		events = append(events, pr49Round3Scan(fmt.Sprintf("2001:db8:1:%x::1", i), 3, now.Add(-time.Second))...)
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 1 {
		t.Fatal("fixture must create one /48 incident")
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	if blocks.Load() != 32 || len(e.respCap[created[0].IncidentID]) != 32 {
		t.Fatal("fixture must exhaust the 32-address budget")
	}
	events = nil
	for i := 0; i < 256; i++ {
		flows := pr49Round3Scan(fmt.Sprintf("2001:db8:1:%x::1", 0x100+i), 3, now.Add(time.Minute))
		for _, ev := range flows {
			ev.DstPort = 22
		}
		events = append(events, flows...)
	}
	_, updated := e.applyEvents(events, now.Add(time.Minute+time.Second))
	if len(updated) != 1 || len(updated[0].Members) != 256 || updated[0].MembersDropped != 32 {
		t.Fatal("fixture must evict the original 32 sources from the member sample")
	}
	for i := 1; i <= 32; i++ {
		if len(updated[0].MemberRules(fmt.Sprintf("2001:db8:1:%x::1", i))) != 0 {
			t.Fatal("a blocked address unexpectedly remains in the member sample")
		}
	}
	e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute+time.Second))
	// 32 резерва и 32 итога блоков; адреса только с долбёжкой не дают ни строки.
	if blocks.Load() != 32 || len(f.rows("response_log")) != 64 {
		t.Fatal("hammer-only addresses must not produce blocks or response decisions")
	}
	old := pr49PersistedIncident(t, updated[0])
	pr49FollowupSaveResponses(f)
	restarted := scanEngine(t, f, 32, ipsConfig(srv))
	restarted.reg = incidents.NewRegistry(100, []incidents.Incident{old})
	restarted.restoreRespState([]incidents.Incident{old}, now.Add(2*time.Minute))
	_, updated = restarted.applyEvents(pr49Round3Scan("2001:db8:1:300::1", 3, now.Add(2*time.Minute)), now.Add(2*time.Minute+time.Second))
	if len(updated) != 1 || updated[0].IncidentID != old.IncidentID {
		t.Fatal("new source must join the same restored /48 incident")
	}
	restarted.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(2*time.Minute+time.Second))
	if got := blocks.Load(); got != 32 {
		t.Fatalf("member eviction reset a fully journaled block_cap=32/1h: blocks=%d, restored reservations=%d",
			got, len(restarted.respCap[old.IncidentID]))
	}
}
