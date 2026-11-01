package eval

import (
	"slices"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// PR #76: T1078 требует признака использования учётной записи. География,
// отказ в доступе или HTTP 200 от общедоступной страницы этого не доказывают.
// https://attack.mitre.org/techniques/T1078/
func TestPR76ForeignAccessRequiresAccountEvidence(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/proxy-foreign-access.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, outcome, status, actor, kind, object string
		wantAccount                                bool
	}{
		{"authenticated access", "success", "200", "fixture-user", "user", "/account", true},
		{"rejected credentials", "failure", "401", "fixture-user", "user", "/login", false},
		{"anonymous unauthorized", "failure", "401", "", "unknown", "/account", false},
		{"anonymous forbidden", "deny", "403", "", "unknown", "/account", false},
		{"anonymous public page", "success", "200", "", "unknown", "/", false},
		{"anonymous login redirect", "success", "302", "", "unknown", "/account", false},
		{"IP actor is not an account", "success", "200", "198.51.100.76", "unknown", "/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
			var events []*model.Event
			for i := 0; i < 5; i++ {
				events = append(events, &model.Event{
					TS:     model.FormatTS(start.Add(time.Duration(i) * time.Minute)),
					Source: "proxy.nginx", SourceClass: "proxy", Action: "proxy.access", Outcome: tc.outcome,
					SrcIP: "198.51.100.76", DstIP: "10.20.0.10", DstPort: 443, Node: "proxy-01",
					ActorName: tc.actor, ActorKind: tc.kind, Object: tc.object,
					Attrs: map[string]string{"country": "DE", "method": "GET", "status": tc.status},
				})
			}
			if got := Run([]*rules.Rule{r}, events[:4]); len(got) != 0 {
				t.Fatalf("four requests must remain below threshold: %+v", got)
			}
			dets := Run([]*rules.Rule{r}, events)
			if tc.wantAccount {
				if len(dets) != 1 || dets[0].Key != "198.51.100.76" || len(dets[0].Events) != 5 {
					t.Fatalf("authenticated foreign access must retain grouping and evidence: %+v", dets)
				}
				for _, tag := range []string{"attack.initial_access", "attack.t1078"} {
					if !slices.Contains(dets[0].Rule.Tags, tag) {
						t.Errorf("authenticated foreign access is missing %s: %v", tag, dets[0].Rule.Tags)
					}
				}
				return
			}
			// Допустим отдельный географический сигнал, но без утверждения
			// об использовании Valid Accounts на этих пяти запросах.
			for _, d := range dets {
				if slices.Contains(d.Rule.Tags, "attack.t1078") {
					t.Fatalf("outcome=%s status=%s actor=%q kind=%s falsely asserts Valid Accounts: %v",
						tc.outcome, tc.status, tc.actor, tc.kind, d.Rule.Tags)
				}
			}
		})
	}
}
