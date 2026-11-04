package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

// These selection spellings are equivalent under the supported rule matcher.
// Recovery must follow the meaning of a rule that opened the incident, for
// both a live reload and an incident restored from its persisted JSON fields.
func TestPR99Round5RuleRecoveryWithEquivalentActionSelectors(t *testing.T) {
	for _, tc := range []struct{ name, action string }{
		{"scalar_control", "rules.rejected"},
		{"single_element_list", "[rules.rejected]"},
		{"case_insensitive_scalar", "RULES.REJECTED"},
	} {
		for _, phase := range []string{"reload", "startup"} {
			t.Run(tc.name+"/"+phase, func(t *testing.T) {
				ops := strings.Replace(pr99Round5OpsRule(t), "    action: rules.rejected\n", "    action: "+tc.action+"\n", 1)
				dir := rulesDirWith(t, map[string]string{"ops.yml": ops, "custom.yml": pr99Round5GoodRule})
				f := newFakeCH(t)
				e := testEngine(t, f, dir, respond.Config{Mode: respond.ModeIDS}, "fixture", "fixture")
				pr99Round5WriteRule(t, dir, pr99Round5GoodRule+"  group_by_next: object\n")
				if rejected := e.maybeReload(true); len(rejected) != 1 || len(e.rulesPending) != 1 {
					t.Fatalf("fixture must reject custom.yml: rejected=%+v pending=%+v", rejected, e.rulesPending)
				}
				rejectedAt := time.Now().Add(-time.Minute)
				e.rulesPending[0].TS = model.FormatTS(rejectedAt)
				e.rulesPending[0].ReceivedAt = rejectedAt
				created, _, _ := e.reg.Apply(eval.Run(e.current(), e.rulesPending), rejectedAt)
				if len(created) != 1 || created[0].RuleID != "a41c-ops-068" || created[0].GroupKey != "custom.yml" {
					t.Fatalf("equivalent selector must open the same rejection incident: %+v", created)
				}
				encoded, err := json.Marshal(created[0])
				if err != nil {
					t.Fatal(err)
				}
				e.flushRulesEvents(context.Background())
				pr99Round5WriteRule(t, dir, pr99Round5GoodRule)
				if phase == "startup" {
					var persisted incidents.Incident
					if err := json.Unmarshal(encoded, &persisted); err != nil {
						t.Fatal(err)
					}
					e = testEngine(t, f, dir, respond.Config{Mode: respond.ModeIDS}, "fixture", "fixture")
					e.noteRejected(nil, e.current(), time.Now())
					e.reg = incidents.NewRegistry(1, []incidents.Incident{persisted})
					e.reloadMu.Lock()
					e.noteRecovered(time.Now())
					e.reloadMu.Unlock()
				} else if rejected := e.maybeReload(true); len(rejected) != 0 {
					t.Fatalf("repair must load: %+v", rejected)
				}
				if e.ruleFor("pr99-round5-custom") == nil || e.m.rulesRejected.Load() != 0 {
					t.Fatal("repaired detector must be active with a zero rejection gauge")
				}
				pr99Round5DrainRuleEvents(t, e, f)
				if open := e.reg.OpenByRule("a41c-ops-068"); open != nil {
					t.Errorf("supported action selector %s prevents recovery: incident=%s file=%s events=%+v",
						tc.action, open.IncidentID, open.GroupKey, eventsOf(t, f))
				}
			})
		}
	}
}
