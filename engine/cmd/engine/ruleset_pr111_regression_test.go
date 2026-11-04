package main

// Регрессии PR #111; ожидают исправленного поведения, без expectedFailure.
// Запуск: cd engine && go test ./cmd/engine -run '^TestPR111' -count=1

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func TestPR111RejectedRulesReachShippedOpsDetection(t *testing.T) {
	t.Setenv("INTERNAL_NETS", "")
	shipped, err := rules.Load(repoRulesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{rejectShippedIDTaken, rejectDuplicateID, rejectParseError} {
		t.Run(reason, func(t *testing.T) {
			ev := rulesRejectedEvent(time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC), "qa-clickhouse", "user/broken.yml", "qa-rule", reason)
			detections := eval.Run(shipped, []*model.Event{ev})
			for _, detection := range detections {
				for _, tag := range detection.Rule.Tags {
					if strings.HasPrefix(tag, "ops.") {
						return
					}
				}
			}
			t.Fatalf("rules.rejected (%s) produces no shipped ops detection; isCandidate=%v, detections=%d", reason, isCandidate(shipped, ev), len(detections))
		})
	}
}

func TestPR111UserRulePermissionChangesTriggerReload(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires POSIX permissions and an unprivileged user, as in the engine image")
	}
	for _, restore := range []bool{true, false} {
		name := "revoke_read_permission"
		if restore {
			name = "restore_read_permission"
		}
		t.Run(name, func(t *testing.T) {
			shipped := rulesDirWith(t, map[string]string{"shipped.yml": simpleRule("qa-shipped", "shipped.action")})
			user := rulesDirWith(t, map[string]string{
				"affected.yml": simpleRule("qa-affected", "custom.action"),
				"other.yml":    simpleRule("qa-other", "other.action"),
			})
			path := filepath.Join(user, "affected.yml")
			if err := os.Chmod(path, 0); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			if _, err := os.ReadFile(path); !os.IsPermission(err) {
				t.Skipf("filesystem does not enforce fixture read permissions: %v", err)
			}
			if !restore {
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			dirs := ruleSet{shipped: shipped, user: user}
			loaded, rejected, err := dirs.load()
			if err != nil {
				t.Fatal(err)
			}
			initialRules := 3
			if restore {
				initialRules = 1
			}
			if len(loaded) != initialRules {
				t.Fatalf("invalid setup: loaded=%d, expected=%d, rejected=%+v", len(loaded), initialRules, rejected)
			}
			// maybeReload использует только эти поля. Отменённый контекст не
			// позволяет best-effort записи отказа обращаться к сети.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			e := &engine{
				dirs: dirs, rulesSig: dirs.signature(), ctx: ctx,
				ch: store.New("http://qa.invalid:8123", "argus", "qa", ""),
			}
			e.rules.Store(&loaded)
			e.m.rulesRejected.Store(int64(len(rejected)))
			mode := os.FileMode(0)
			wantRules, wantRejected := 1, int64(1)
			if restore {
				mode, wantRules, wantRejected = 0o600, 3, 0
			}
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			e.maybeReload(false)
			if len(e.current()) != wantRules || e.m.rulesRejected.Load() != wantRejected {
				t.Fatalf("permission-only change was ignored: active rules=%d rejected=%d; want rules=%d rejected=%d", len(e.current()), e.m.rulesRejected.Load(), wantRules, wantRejected)
			}
		})
	}
}

func TestPR111ShippedIDReasonDoesNotDependOnSubdirectoryName(t *testing.T) {
	shipped := t.TempDir()
	if err := os.Mkdir(filepath.Join(shipped, "user"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shipped, "user", "shipped.yml"), []byte(simpleRule("qa-shipped", "shipped.action")), 0o600); err != nil {
		t.Fatal(err)
	}
	user := rulesDirWith(t, map[string]string{
		"override.yml": simpleRule("qa-shipped", "override.action"),
		"first.yml":    simpleRule("qa-custom", "custom.action"),
		"second.yml":   simpleRule("qa-custom", "duplicate.action"),
	})
	dirs := ruleSet{shipped: shipped, user: user}
	loaded, rejected, err := dirs.load()
	if err != nil || len(loaded) != 2 || len(rejected) != 2 {
		t.Fatalf("rules=%d rejected=%+v err=%v", len(loaded), rejected, err)
	}
	if file, action := ruleByID(t, dirs, "qa-shipped"); file != "user/shipped.yml" || action != "shipped.action" {
		t.Fatalf("shipped rule was replaced: file=%q action=%q", file, action)
	}
	for _, rejection := range rejected {
		want := rejectDuplicateID
		if rejection.ID == "qa-shipped" {
			want = rejectShippedIDTaken
		}
		if rejection.Reason != want {
			t.Errorf("rejected %q: got %q, want %q; shipped/user origin cannot be inferred from Rule.File", rejection.ID, rejection.Reason, want)
		}
	}
}
