package incidents

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr49CollapsedRule(id string) *rules.Rule {
	r := &rules.Rule{ID: id, Title: id, Level: "medium", AutoClose: "2h",
		Collapse: &rules.Collapse{By: "src.net", Group: "inbound-scan", BlockCap: 32, BlockCapWindow: "1h"}}
	r.Detection.Threshold = &rules.Threshold{Kind: "count", Count: 1, GroupBy: "src.ip", Window: "10m"}
	return r
}

func pr49Detection(r *rules.Rule, ip string, at time.Time, count int) eval.Detection {
	events := make([]*model.Event, count)
	for i := range events {
		events[i] = &model.Event{TS: model.FormatTS(at.Add(time.Duration(i) * time.Millisecond)),
			Source: "netflow.fixture", SourceClass: "netflow", Action: "flow", SrcIP: ip,
			Attrs: map[string]string{"transport": "file"}}
	}
	return eval.Detection{Rule: r, Key: ip, Events: events, First: events[0].Time(), Last: events[len(events)-1].Time()}
}

// A retained address gets a new event, but no new address arrives: the count
// of omitted addresses must stay one, including after serializing the row.
func TestPR49MembersDroppedCountsDistinctOmittedAddresses(t *testing.T) {
	r := pr49CollapsedRule("scan")
	reg := NewRegistry(0, nil)
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var inc *Incident
	for i := 0; i <= maxMembers; i++ {
		d := pr49Detection(r, fmt.Sprintf("2001:db8:1:%x::1", i), start.Add(time.Duration(i)*time.Second), 1)
		created, updated, _ := reg.Apply([]eval.Detection{d}, d.Last)
		if i == 0 {
			if len(created) != 1 {
				t.Fatal("fixture must create one subnet incident")
			}
			inc = created[0]
		} else if len(created) != 0 || len(updated) != 1 {
			t.Fatalf("address %d did not join the existing /48", i)
		}
	}
	if len(inc.Members) != maxMembers || inc.MembersDropped != 1 {
		t.Fatalf("initial overflow: members=%d dropped=%d", len(inc.Members), inc.MembersDropped)
	}
	ip := fmt.Sprintf("2001:db8:1:%x::1", maxMembers)
	d := pr49Detection(r, ip, start.Add(5*time.Minute), 2)
	reg.Apply([]eval.Detection{d}, d.Last)
	raw, err := json.Marshal(inc)
	if err != nil {
		t.Fatal(err)
	}
	var persisted Incident
	if err := json.Unmarshal(raw, &persisted); err != nil {
		t.Fatal(err)
	}
	if got := len(persisted.Members) + int(persisted.MembersDropped); got != maxMembers+1 {
		t.Fatalf("same 257 addresses reported as %d: members_dropped=%d; an evicted address was counted twice", got, persisted.MembersDropped)
	}
}

// Each Apply is a fresh, small input buffer. Rotating /64s inside a single
// /48 must not retain every historical event behind the advertised 2,000 cap.
func TestPR49CollapsedEventRetentionIsBounded(t *testing.T) {
	r := pr49CollapsedRule("scan")
	reg := NewRegistry(0, nil)
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var inc *Incident
	for i := 0; i < 300; i++ {
		d := pr49Detection(r, fmt.Sprintf("2001:db8:1:%x::1", i), start.Add(time.Duration(i)*time.Second), 8)
		created, _, _ := reg.Apply([]eval.Detection{d}, d.Last)
		if len(created) == 1 {
			inc = created[0]
		}
	}
	if inc == nil || len(reg.open) != 1 {
		t.Fatal("fixture must keep one open /48 incident")
	}
	retained := make(map[*model.Event]bool)
	for _, event := range inc.Events {
		retained[event] = true
	}
	for _, part := range inc.parts {
		for _, event := range part.events {
			retained[event] = true
		}
	}
	if len(retained) > maxCollapsedEvents {
		t.Fatalf("incident retains %d events through %d parts despite Events=%d and members=%d; rotating addresses bypasses the memory cap",
			len(retained), len(inc.parts), len(inc.Events), len(inc.Members))
	}
}

// Replaying a small new window for a known address must preserve the saved
// first observation and other rules that fired before the restart.
func TestPR49RestartPreservesMemberHistory(t *testing.T) {
	start := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	r := pr49CollapsedRule("scan")
	ip := "203.0.113.7"
	old := Incident{IncidentID: "INC-7", RuleID: r.ID, RuleTitle: r.Title, Level: r.Level, Status: StatusNew,
		ActorName: "203.0.113.0/24", GroupKey: CollapsedKey("inbound-scan", "203.0.113.0/24"),
		CreatedAt: model.FormatTS(start)[:19], UpdatedAt: model.FormatTS(start.Add(time.Minute))[:19],
		FirstTS: model.FormatTS(start), LastTS: model.FormatTS(start.Add(time.Minute)), EventCount: 60,
		Members: MemberList{{IP: ip, First: model.FormatTS(start), Last: model.FormatTS(start.Add(time.Minute)),
			Events: 60, Rules: []string{"hammer", "scan"}}}}
	raw, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	var restored Incident
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	reg := NewRegistry(7, []Incident{restored})
	d := pr49Detection(r, ip, start.Add(15*time.Minute), 3)
	created, updated, _ := reg.Apply([]eval.Detection{d}, d.Last)
	if len(created) != 0 || len(updated) != 1 || len(updated[0].Members) != 1 {
		t.Fatalf("unexpected restored update: created=%d updated=%d", len(created), len(updated))
	}
	m := updated[0].Members[0]
	if m.First != old.Members[0].First || !slices.Contains(m.Rules, "hammer") || !slices.Contains(m.Rules, "scan") {
		t.Fatalf("saved address history overwritten: got %+v; original %+v", m, old.Members[0])
	}
}
