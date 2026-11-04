package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

const pr99Round5GoodRule = "title: Custom\nid: pr99-round5-custom\ndetection:\n  selection: {action: fixture.failure}\n"

func pr99Round5OpsRule(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "ops", "rules-rejected.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func pr99Round5WriteRule(t *testing.T, dir, raw string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "custom.yml"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Use the real cycle and INSERT path. The fake store returns all recorded rule
// events as the retained event buffer, including a recovery from a later tick.
// Do not force another reload: an unchanged catalog is normal after a repair.
func pr99Round5DrainRuleEvents(t *testing.T, e *engine, f *fakeCH) {
	t.Helper()
	ctx := context.Background()
	e.flushRulesEvents(ctx)
	for tick := 0; tick < 3; tick++ {
		if rejected := e.maybeReload(false); len(rejected) != 0 {
			t.Fatalf("idle catalog rejected rules: %+v", rejected)
		}
		stored := eventsOf(t, f)
		buffer := make([]*model.Event, len(stored))
		for i := range stored {
			buffer[i] = &stored[i]
		}
		e.cycle(ctx, e.current(), buffer)
		e.flushRulesEvents(ctx)
	}
}

// A rejection can be queued or already stored while its incident has not yet
// been created by the next poll. Repairing in that interval must not leave a
// permanent high-severity incident for an active rule with a zero rejection
// gauge. The first case is the control where the incident exists in time.
func TestPR99Round5RuleRecoveryBeforeRejectionIsConsumed(t *testing.T) {
	for _, phase := range []string{
		"incident_exists_control",
		"repair_before_flush",
		"repair_before_poll",
		"restart_before_poll",
	} {
		t.Run(phase, func(t *testing.T) {
			dir := rulesDirWith(t, map[string]string{
				"ops.yml": pr99Round5OpsRule(t), "custom.yml": pr99Round5GoodRule,
			})
			f := newFakeCH(t)
			e := testEngine(t, f, dir, respond.Config{Mode: respond.ModeIDS}, "fixture", "fixture")
			pr99Round5WriteRule(t, dir, pr99Round5GoodRule+"  group_by_next: object\n")
			if rejected := e.maybeReload(true); len(rejected) != 1 || rejected[0].File != "custom.yml" {
				t.Fatalf("fixture must reject custom.yml: %+v", rejected)
			}
			if len(e.rulesPending) != 1 || e.rulesPending[0].Action != "rules.rejected" {
				t.Fatalf("fixture must queue a rejection: %+v", e.rulesPending)
			}
			// Model an elapsed polling interval without sleeps or timestamp ties.
			rejectedAt := time.Now().Add(-time.Minute)
			e.rulesPending[0].TS = model.FormatTS(rejectedAt)
			e.rulesPending[0].ReceivedAt = rejectedAt
			if phase == "incident_exists_control" {
				created, _, _ := e.reg.Apply(eval.Run(e.current(), e.rulesPending), rejectedAt)
				if len(created) != 1 || created[0].RuleID != "a41c-ops-068" || created[0].GroupKey != "custom.yml" {
					t.Fatalf("control must open the rejection incident: %+v", created)
				}
			}
			if phase != "repair_before_flush" {
				e.flushRulesEvents(context.Background())
				if got := len(eventsOf(t, f)); got != 1 {
					t.Fatalf("fixture must persist the rejection: events=%d", got)
				}
			}

			pr99Round5WriteRule(t, dir, pr99Round5GoodRule)
			if phase == "restart_before_poll" {
				// The rejection is durable, but no incident existed before the
				// restart. Follow run's load -> restore registry -> recover order.
				e = testEngine(t, f, dir, respond.Config{Mode: respond.ModeIDS}, "fixture", "fixture")
				e.noteRejected(nil, e.current(), time.Now())
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
				t.Errorf("repaired rule still has an open rejection after polling: incident=%s file=%s status=%s events=%+v",
					open.IncidentID, open.GroupKey, open.Status, eventsOf(t, f))
			}
		})
	}
}
