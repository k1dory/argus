package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
)

// Склеенный по подсети инцидент (0035): адреса переживают запись в incidents и
// чтение OpenIncidents — по ним после рестарта решается, кого уже блокировали.
func TestLiveCollapsedMembersRoundTrip(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	n := 900000000 + int(time.Now().UnixNano()%90000000)
	now := time.Now().UTC().Truncate(time.Second)
	in := inc(fmt.Sprintf("INC-%d", n), "collapse.live."+sfx, incidents.StatusNew, "medium", "203.0.113.0/24", "", now.Add(-time.Hour))
	in.GroupKey = incidents.CollapsedKey("inbound-scan-"+sfx, "203.0.113.0/24")
	in.Members = incidents.MemberList{
		{IP: "203.0.113.10", First: "2026-11-01 10:00:00.000", Last: "2026-11-01 10:05:00.000", Events: 9, Rules: []string{"a41c-net-070", "a41c-net-072"}},
		{IP: "203.0.113.20", First: "2026-11-01 10:01:00.000", Last: "2026-11-01 10:02:00.000", Events: 5, Rules: []string{"a41c-net-071"}},
	}
	in.MembersDropped = 3
	if err := c.InsertIncidents(ctx, []*incidents.Incident{in}); err != nil {
		t.Fatal(err)
	}
	open, _, err := c.OpenIncidents(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range open {
		if row.IncidentID != in.IncidentID {
			continue
		}
		if row.GroupKey != in.GroupKey || row.MembersDropped != 3 || fmt.Sprint(row.Members) != fmt.Sprint(in.Members) {
			t.Fatalf("restored: group=%q dropped=%d members=%+v", row.GroupKey, row.MembersDropped, row.Members)
		}
		return
	}
	t.Fatal("fixture incident not restored")
}
