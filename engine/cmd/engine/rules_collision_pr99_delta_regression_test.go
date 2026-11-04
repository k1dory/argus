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

// A rejected file keeps its old Rule, but policy selection uses the first rule
// with the same ID. The combined snapshot must be checked for collisions after
// retaining old files, even when the new on-disk IDs themselves are distinct.
func TestPR99DeltaRejectedReloadCannotShadowRetainedRule(t *testing.T) {
	const harmless = "title: Unrelated rule\nid: pr99-harmless\nlevel: low\ndetection:\n  selection: {action: other.event}\n"
	const protected = "title: Protected detection\nid: pr99-protected\nlevel: critical\ndetection:\n  selection: {action: test.failure}\nrespond: {action: block_ip, target: src.ip, min_events: 1}\n"
	for _, tc := range []struct {
		name                         string
		distinctDiskIDs, overlapping bool
	}{
		{"duplicate_ids_on_disk", false, false},
		{"collision_only_after_fallback", true, false},
		{"overlap_suppresses_critical_detection", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := rulesDirWith(t, map[string]string{"a-other.yml": harmless, "z-protected.yml": protected})
			initial, err := rules.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			e := &engine{
				dirs: ruleSet{shipped: dir}, rulesSig: signature(dir), token: "fixture", mtoken: "fixture",
				resp: respond.New(respond.Config{Mode: respond.ModeIDS, ManualTTL: "1h"}),
			}
			e.rules.Store(&initial)
			old := e.ruleFor("pr99-protected")
			if old == nil || old.Respond == nil {
				t.Fatal("fixture must initially have an active response policy")
			}

			// One valid edit takes an ID that the retained version still owns.
			nextOther := strings.Replace(harmless, "pr99-harmless", "pr99-protected", 1)
			if tc.overlapping {
				nextOther = strings.Replace(nextOther, "other.event", "test.failure", 1)
			}
			nextProtected := strings.Replace(protected, "  selection:", "  group_by_next: attrs.peer\n  selection:", 1)
			if tc.distinctDiskIDs {
				nextProtected = strings.Replace(nextProtected, "pr99-protected", "pr99-protected-v2", 1)
			}
			for file, raw := range map[string]string{"a-other.yml": nextOther, "z-protected.yml": nextProtected} {
				if err := os.WriteFile(filepath.Join(dir, file), []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			code, body := do(t, e.handler(), http.MethodPost, "/reload", "fixture", "")
			var response struct {
				Rejected []struct{ File, Error string }
			}
			if err := json.Unmarshal([]byte(body), &response); err != nil || code != http.StatusUnprocessableEntity {
				t.Fatalf("unsupported file must be reported as 422: status=%d body=%s err=%v", code, body, err)
			}
			reported := map[string]bool{}
			for _, rejection := range response.Rejected {
				reported[rejection.File] = true
			}
			if !reported["z-protected.yml"] || e.m.reloadFailures.Load() != 1 {
				t.Fatalf("fixture rejection not observed: body=%s failures=%d", body, e.m.reloadFailures.Load())
			}

			// A non-overlapping duplicate shadows response/analyst policy.
			// An overlapping one also consumes the same registry key before
			// the retained critical detector, losing its severity/escalation.
			now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			event := &model.Event{TS: model.FormatTS(now), Action: "test.failure", ActorName: "alice", Node: "edge", SrcIP: "203.0.113.9"}
			created, _, _ := incidents.NewRegistry(0, nil).Apply(eval.Run(e.current(), []*model.Event{event}), now)
			if len(created) != 1 {
				t.Fatalf("expected one protected incident: %+v", created)
			}
			if created[0].RuleID != old.ID || created[0].RuleTitle != old.Title || created[0].Level != old.Level || created[0].Status != incidents.StatusEscalated {
				t.Errorf("retained critical detection was shadowed: %+v", created[0])
			}
			selected := e.ruleFor(created[0].RuleID)
			if selected == nil || selected.Respond == nil || selected.Respond.Action != old.Respond.Action || selected.File != old.File {
				t.Errorf("retained detector's response policy was shadowed: selected=%+v; expected file=%s respond=%+v", selected, old.File, old.Respond)
			}
			seen := map[string]string{}
			for _, r := range e.current() {
				if file, exists := seen[r.ID]; exists {
					t.Errorf("active snapshot contains duplicate id %q in %s and %s", r.ID, file, r.File)
				}
				seen[r.ID] = r.File
			}
		})
	}
}
