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

// ResponsesFor читает решения по адресам склеенного инцидента из response_log:
// только свои инциденты, только записи с адресом, не старше since.
func TestLiveResponsesForRestoresPerAddressDecisions(t *testing.T) {
	c := liveStore(t)
	applyMigrations(t, c)
	ctx := context.Background()
	sfx := suffix(t)
	id, other := "INC-resp-"+sfx, "INC-other-"+sfx
	now := time.Now().UTC().Truncate(time.Second)
	ts := func(d time.Duration) string { return now.Add(d).Format("2006-01-02 15:04:05") }
	rows := []ResponseRow{
		{TS: ts(-3 * time.Hour), IncidentID: id, IP: "203.0.113.1", Mode: "ips", Executor: "ngfw.edge", OK: 1, Detail: "old"},
		{TS: ts(-time.Minute), IncidentID: id, IP: "203.0.113.2", Mode: "ips", Executor: "ngfw.edge", OK: 1, Detail: "POST"},
		{TS: ts(-time.Minute), IncidentID: id, IP: "", Mode: "ips", Executor: "argus", OK: 1, Detail: "без адреса"},
		{TS: ts(-time.Minute), IncidentID: other, IP: "203.0.113.3", Mode: "ips", Executor: "ngfw.edge", OK: 1, Detail: "чужой"},
	}
	if err := c.InsertResponses(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := c.ResponsesFor(ctx, []string{id}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "203.0.113.2" || got[0].OK != 1 || got[0].Executor != "ngfw.edge" {
		t.Fatalf("ResponsesFor: %+v", got)
	}
}
