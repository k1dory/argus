package eval

import (
	"slices"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// actor.kind classifies an actor; it does not supply an account identity.
// A successful public-page request with an absent/blank actor.name must stay
// a geographic signal, not become T1078 grouped by the fallback proxy node.
func TestPR105ForeignAccountRequiresNonblankIdentity(t *testing.T) {
	geo, err := rules.LoadFile("../../../rules/proxy-foreign-access.yml")
	if err != nil {
		t.Fatal(err)
	}
	account, err := rules.LoadFile("../../../rules/proxy-foreign-account.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, actor, kind, outcome, status, country string
		wantAccount, wantGeo                        bool
	}{
		{"no account identity", "", "user", "success", "200", "DE", false, true},
		{"whitespace account identity", " \t ", "user", "success", "200", "DE", false, true},
		{"named successful user", "alice", "user", "success", "200", "DE", true, true},
		{"named rejected user", "alice", "user", "failure", "401", "DE", false, true},
		{"anonymous control", "", "unknown", "success", "200", "DE", false, true},
		{"home country control", "alice", "user", "success", "200", "ru", false, false},
		{"unknown country control", "alice", "user", "success", "200", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			var events []*model.Event
			for i := 0; i < 5; i++ {
				event := &model.Event{
					TS:     model.FormatTS(start.Add(time.Duration(i) * time.Minute)),
					Source: "proxy.fixture", SourceClass: "proxy", Action: "proxy.access", Outcome: tc.outcome,
					ActorName: tc.actor, ActorKind: tc.kind, SrcIP: "198.51.100.42", Node: "portal.example", Object: "/",
					Attrs: map[string]string{"country": tc.country, "status": tc.status, "method": "GET"},
				}
				event.Ensure()
				events = append(events, event)
			}
			detections := Run([]*rules.Rule{geo, account}, events)
			geoCount, accountCount := 0, 0
			for _, detection := range detections {
				switch detection.Rule.ID {
				case geo.ID:
					geoCount++
					if detection.Key != events[0].SrcIP || len(detection.Events) != len(events) || slices.Contains(detection.Rule.Tags, "attack.t1078") {
						t.Errorf("geographic signal lost its grouping/evidence or gained T1078: %+v", detection)
					}
				case account.ID:
					accountCount++
					if !tc.wantAccount {
						t.Errorf("actor=%q kind=%q outcome=%q produced an account incident with key %q", tc.actor, tc.kind, tc.outcome, detection.Key)
					}
					if tc.wantAccount && (detection.Key != tc.actor || len(detection.Events) != len(events) || !slices.Contains(detection.Rule.Tags, "attack.t1078")) {
						t.Errorf("named user's T1078 detection lost account grouping/evidence: %+v", detection)
					}
				default:
					t.Errorf("unexpected rule: %s", detection.Rule.ID)
				}
			}
			if (geoCount == 1) != tc.wantGeo || geoCount > 1 {
				t.Errorf("geographic incidents=%d, want presence=%t", geoCount, tc.wantGeo)
			}
			if (accountCount == 1) != tc.wantAccount || accountCount > 1 {
				t.Errorf("account incidents=%d, want presence=%t", accountCount, tc.wantAccount)
			}
		})
	}
}
