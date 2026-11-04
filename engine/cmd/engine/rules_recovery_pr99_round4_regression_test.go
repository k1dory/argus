package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr99Round4StartupState(t *testing.T, dir string, open []incidents.Incident, now time.Time) *engine {
	t.Helper()
	rs, rejected := loadForRun(ruleSet{shipped: dir})
	e := &engine{
		dirs: ruleSet{shipped: dir}, rulesSig: signature(dir), token: "fixture", mtoken: "fixture",
		resp: respond.New(respond.Config{Mode: respond.ModeIDS, ManualTTL: "1h"}),
	}
	e.rules.Store(&rs)
	e.m.rulesRejected.Store(int64(len(rejected)))
	// Preserve run's startup order: record rule load, then restore incidents.
	e.noteRejected(rejected, rs, now)
	e.reg = incidents.NewRegistry(1, open)
	return e
}

// Recovery must reach an already open a41c-ops-068 incident even if the file
// temporarily disappeared, or the repair was deployed with an engine restart.
// Both are ordinary ways to fix an incompatible rule or a duplicate file.
func TestPR99Round4RuleRecoverySurvivesStateDiscontinuity(t *testing.T) {
	ops, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "ops", "rules-rejected.yml"))
	if err != nil {
		t.Fatal(err)
	}
	const good = "title: Custom\nid: pr99-round4-custom\ndetection:\n  selection: {action: test.failure}\n"
	for _, mode := range []string{"live_repair_control", "temporarily_removed", "engine_restarted"} {
		t.Run(mode, func(t *testing.T) {
			dir := rulesDirWith(t, map[string]string{
				"ops.yml": string(ops), "custom.yml": good + "  group_by_next: attrs.peer\n",
			})
			now := time.Now().Add(-time.Minute)
			e := pr99Round4StartupState(t, dir, nil, now)
			if len(e.rulesPending) != 1 || e.rulesPending[0].Action != "rules.rejected" {
				t.Fatalf("fixture must emit the original rejection: %+v", e.rulesPending)
			}
			created, _, _ := e.reg.Apply(eval.Run(e.current(), e.rulesPending), now)
			if len(created) != 1 || created[0].RuleID != "a41c-ops-068" || created[0].GroupKey != "shipped/custom.yml" {
				t.Fatalf("fixture must open the file's operational incident: %+v", created)
			}
			// Retain only the public persisted state, as ClickHouse does.
			encoded, err := json.Marshal(created[0])
			if err != nil {
				t.Fatal(err)
			}
			var persisted incidents.Incident
			if err := json.Unmarshal(encoded, &persisted); err != nil {
				t.Fatal(err)
			}
			e.rulesPending = nil // Original rejection was successfully delivered.
			path := filepath.Join(dir, "custom.yml")
			if mode == "temporarily_removed" {
				if err := os.Rename(path, path+".disabled"); err != nil {
					t.Fatal(err)
				}
				if rejected := e.maybeReload(true); len(rejected) != 0 {
					t.Fatalf("temporary removal: %+v", rejected)
				}
			}
			if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
				t.Fatal(err)
			}
			if mode == "engine_restarted" {
				e = pr99Round4StartupState(t, dir, []incidents.Incident{persisted}, now.Add(30*time.Second))
			}
			// A forced reload after restoration also must not leave the stale
			// incident forever: run's normal signature check would skip it.
			if rejected := e.maybeReload(true); len(rejected) != 0 {
				t.Fatalf("corrected file must load: %+v", rejected)
			}
			if e.ruleFor("pr99-round4-custom") == nil {
				t.Fatal("corrected detector did not become active")
			}
			code, metrics := do(t, e.handler(), http.MethodGet, "/metrics", "fixture", "")
			if code != http.StatusOK || !strings.Contains(metrics, "\nargus_engine_rules_rejected 0\n") {
				t.Fatalf("repaired catalog must expose zero rejections: HTTP %d %s", code, metrics)
			}
			_, closers := eval.Evaluate(eval.Input{Rules: e.current(), Events: e.rulesPending})
			for _, c := range closers {
				e.reg.Close(c.Rule.ID, c.Key, "fixture: rule recovered", c.Event.Time(), time.Now())
			}
			if open := e.reg.OpenByRule("a41c-ops-068"); open != nil {
				t.Errorf("rule is active and gauge is zero, but recovery was lost: incident=%s file=%s pending=%+v", open.IncidentID, open.GroupKey, e.rulesPending)
			}
		})
	}
}

// Ingest overwrites the claimed internal origin. Check both opening and closing
// against the shipped rule; a forged recovery must not close the real incident.
func TestPR99Round4RuleRejectionRequiresInternalTransport(t *testing.T) {
	r, err := rules.LoadFile(filepath.Join("..", "..", "..", "rules", "ops", "rules-rejected.yml"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	for _, transport := range []string{"internal", "http", "tcp", "tls", "udp", "file", ""} {
		t.Run(transport, func(t *testing.T) {
			rejected := rulesRejectedEvent(now, "fixture", "custom.yml", "custom", "parse_error")
			rejected.Attrs["transport"] = transport
			if got := len(eval.Run([]*rules.Rule{r}, []*model.Event{rejected})); (got == 1) != (transport == "internal") {
				t.Fatalf("transport=%q produced %d rejection detections", transport, got)
			}
			real := rulesRejectedEvent(now, "fixture", "custom.yml", "custom", "parse_error")
			reg := incidents.NewRegistry(0, nil)
			created, _, _ := reg.Apply(eval.Run([]*rules.Rule{r}, []*model.Event{real}), now)
			if len(created) != 1 {
				t.Fatalf("fixture must open a real rejection incident: %+v", created)
			}
			recovery := rulesRejectedEvent(now.Add(time.Minute), "fixture", "custom.yml", "custom", "")
			recovery.Action, recovery.Outcome = "rules.recovered", "success"
			recovery.Attrs["transport"] = transport
			_, closers := eval.Evaluate(eval.Input{Rules: []*rules.Rule{r}, Events: []*model.Event{recovery}})
			for _, c := range closers {
				reg.Close(c.Rule.ID, c.Key, "fixture: recovery", c.Event.Time(), now.Add(time.Minute))
			}
			if got := created[0].Status == incidents.StatusClosed; got != (transport == "internal") {
				t.Errorf("transport=%q changed the incident incorrectly: status=%s", transport, created[0].Status)
			}
		})
	}
}
