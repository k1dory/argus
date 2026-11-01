package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Positive controls for the security boundaries reviewed alongside the
// failing PR49 regressions. These do not require a deployed ClickHouse/NGFW.
func TestPR49CapReservationsAreAtomicAndReleasable(t *testing.T) {
	e := &engine{respCap: map[string][]time.Time{}}
	now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 96; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.capReserve("INC-7", now, time.Hour, 32) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 32 {
		t.Fatalf("concurrent reservations=%d, want 32", accepted.Load())
	}
	e.capRelease("INC-7", now)
	if !e.capReserve("INC-7", now.Add(time.Minute), time.Hour, 32) || e.capReserve("INC-7", now.Add(time.Minute), time.Hour, 32) {
		t.Fatal("release must return exactly one slot")
	}
	if !e.capReserve("INC-7", now.Add(time.Hour), time.Hour, 32) {
		t.Fatal("expired reservations must cease consuming the hour budget")
	}
}

func TestPR49NeverBlockAndAllowlistReturnCapacity(t *testing.T) {
	for _, policy := range []string{"never_block", "allowlist"} {
		t.Run(policy, func(t *testing.T) {
			f := newFakeCH(t)
			srv, blocks := pr49NGFW(t)
			cfg := ipsConfig(srv)
			if policy == "never_block" {
				cfg.NeverBlock = []string{"203.0.113.1/32"}
			} else {
				cfg.Allowlist = []string{"203.0.113.1/32"}
			}
			e := scanEngine(t, f, 1, cfg)
			now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
			created, _ := e.applyEvents(portScan("203.0.113.1", 3), now)
			if len(created) != 1 {
				t.Fatal("missing protected-address incident")
			}
			e.autoRespond(context.Background(), snapshotIncidents(created), now)
			if blocks.Load() != 0 || len(e.respCap[created[0].IncidentID]) != 0 {
				t.Fatal("protected address was blocked or consumed block capacity")
			}
			_, updated := e.applyEvents(portScan("203.0.113.2", 3), now.Add(time.Minute))
			if len(updated) != 1 {
				t.Fatal("missing second member")
			}
			e.autoRespond(context.Background(), snapshotIncidents(updated), now.Add(time.Minute))
			if blocks.Load() != 1 {
				t.Fatalf("protected address exhausted the only slot: blocks=%d", blocks.Load())
			}
		})
	}
}

func TestPR49IPv6SubnetsShareCapWithin48Only(t *testing.T) {
	f := newFakeCH(t)
	srv, blocks := pr49NGFW(t)
	e := scanEngine(t, f, 32, ipsConfig(srv))
	now := time.Date(2026, 11, 1, 10, 5, 0, 0, time.UTC)
	var events []*model.Event
	for i := 1; i <= 33; i++ {
		for _, ip := range []string{
			fmt.Sprintf("2001:db8:1:%x::1", i), // 33 distinct /64s in one /48
			fmt.Sprintf("2001:db8:2:%x::1", i), // separate /48, separate incident
			fmt.Sprintf("203.0.113.%d", i),
			fmt.Sprintf("198.51.100.%d", i),
		} {
			events = append(events, portScan(ip, 3)...)
		}
	}
	created, _ := e.applyEvents(events, now)
	if len(created) != 4 {
		t.Fatalf("want four subnet incidents, got %d", len(created))
	}
	e.autoRespond(context.Background(), snapshotIncidents(created), now)
	for _, inc := range created {
		if len(inc.Members) != 33 || len(e.respCap[inc.IncidentID]) != 32 {
			t.Errorf("subnet %s: members=%d reserved=%d", inc.ActorName, len(inc.Members), len(e.respCap[inc.IncidentID]))
		}
	}
	if blocks.Load() != 4*32 {
		t.Fatalf("per-incident budgets: blocks=%d, want 128", blocks.Load())
	}
	if mapped, ok := rules.NetKey("::ffff:203.0.113.9"); !ok || mapped != "203.0.113.0/24" {
		t.Fatalf("IPv4-mapped address escaped its /24: %q, ok=%t", mapped, ok)
	}
}
