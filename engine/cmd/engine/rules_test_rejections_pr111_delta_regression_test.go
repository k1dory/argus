package main

import (
	"os"
	"path/filepath"
	"testing"
)

// rules test is a validation command: rejected configured user rules must
// fail it, even when every shipped fixture passes. An explicit --dir still
// deliberately isolates the chosen catalogue. No CLI subprocess is needed.
func TestPR111DeltaRulesTestFailsForRejectedUserRules(t *testing.T) {
	for _, invalid := range []string{"parse_error", "shipped_id_taken", "duplicate_id"} {
		t.Run(invalid, func(t *testing.T) {
			shipped := rulesDirWith(t, map[string]string{
				"shipped.yml": simpleRule("pr111-validation-shipped", "shipped.action"),
			})
			userFiles := map[string]string{"bad.yml": "id: [unterminated\n"}
			switch invalid {
			case "shipped_id_taken":
				userFiles = map[string]string{"bad.yml": simpleRule("pr111-validation-shipped", "user.action")}
			case "duplicate_id":
				userFiles = map[string]string{
					"a.yml": simpleRule("pr111-validation-user", "user.action"),
					"b.yml": simpleRule("pr111-validation-user", "other.action"),
				}
			}
			user := rulesDirWith(t, userFiles)
			t.Setenv("RULES_USER_DIR", user)
			fixture := filepath.Join(t.TempDir(), "events.ndjson")
			if err := os.WriteFile(fixture, []byte(`{"ts":"2026-11-04 12:00:00.000","action":"shipped.action","actor_name":"qa"}`+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			testsDir := filepath.Join(shipped, "tests")
			if err := os.Mkdir(testsDir, 0o700); err != nil {
				t.Fatal(err)
			}
			raw := "rule: pr111-validation-shipped\nfixture: " + fixture + "\nexpect_incidents: 1\n"
			if err := os.WriteFile(filepath.Join(testsDir, "shipped.yml"), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if code := rulesTest(shipped, []string{"--dir", shipped}); code != 0 {
				t.Fatalf("explicit --dir control must pass: exit %d", code)
			}
			_, rejected, err := (ruleSet{shipped: shipped, user: user}).load()
			if err != nil || len(rejected) != 1 || rejected[0].Reason != invalid {
				t.Fatalf("fixture must reject exactly one user rule/catalogue: rejected=%+v err=%v", rejected, err)
			}
			for _, mode := range []string{"fixtures", "replay"} {
				t.Run(mode, func(t *testing.T) {
					var args []string
					if mode == "replay" {
						args = []string{"--replay", fixture}
					}
					if code := rulesTest(shipped, args); code == 0 {
						t.Fatalf("rules test succeeds despite %s in RULES_USER_DIR; validation must report a nonzero exit status", invalid)
					}
				})
			}
		})
	}
}
