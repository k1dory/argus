package eval

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Go's regexp \S excludes ASCII whitespace only. Unicode space separators
// survive normalized-event ingestion but do not identify an account. They must
// retain the geographic signal without acquiring the T1078 account incident.
func TestPR107ForeignAccountRejectsUnicodeBlankIdentity(t *testing.T) {
	geo, err := rules.LoadFile("../../../rules/proxy-foreign-access.yml")
	if err != nil {
		t.Fatal(err)
	}
	account, err := rules.LoadFile("../../../rules/proxy-foreign-account.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, actor string
		wantAccount bool
	}{
		{"empty control", "", false},
		{"ASCII blank control", " \t ", false},
		{"nonbreaking space", "\u00a0", false},
		{"em space", "\u2003", false},
		{"narrow nonbreaking space", "\u202f", false},
		{"ideographic space", "\u3000", false},
		{"mixed whitespace", " \t\u00a0\u2003\u202f\u3000 ", false},
		{"named ASCII account", "alice", true},
		{"named Unicode account", "Иван", true},
		{"space inside a named account", "Alice\u00a0Smith", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if named := strings.TrimSpace(tc.actor) != ""; named != tc.wantAccount {
				t.Fatal("fixture must distinguish an unnamed account from a named one")
			}
			start := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			var events []*model.Event
			for i := 0; i < 5; i++ {
				e := &model.Event{
					TS:     model.FormatTS(start.Add(time.Duration(i) * time.Minute)),
					Source: "proxy.fixture", SourceClass: "proxy", Action: "proxy.access", Outcome: "success",
					ActorName: tc.actor, ActorKind: "user", Node: "portal.example", SrcIP: "198.51.100.42",
					Object: "/account", Attrs: map[string]string{"country": "DE", "status": "200"},
				}
				e.Ensure()
				events = append(events, e)
			}
			if got := Run([]*rules.Rule{geo}, events); len(got) != 1 || len(got[0].Events) != 5 || slices.Contains(got[0].Rule.Tags, "attack.t1078") {
				t.Fatalf("geographic evidence must remain available without T1078: %+v", got)
			}
			got := Run([]*rules.Rule{account}, events)
			if !tc.wantAccount {
				if len(got) != 0 {
					t.Fatalf("blank actor_name=%q produced an account incident: key=%q events=%d tags=%v",
						tc.actor, got[0].Key, len(got[0].Events), got[0].Rule.Tags)
				}
				return
			}
			if len(got) != 1 || got[0].Key != tc.actor+"|portal.example" || len(got[0].Events) != 5 || !slices.Contains(got[0].Rule.Tags, "attack.t1078") {
				t.Fatalf("named account must retain its service, evidence and T1078: %+v", got)
			}
		})
	}
}
