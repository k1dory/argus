package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/rules"
)

// A newly added file must not turn a surviving shipped detector into a missing
// detector merely by restarting the engine. Either startup must refuse the
// ambiguous configuration, or it must retain the authoritative detector. The
// subprocess permits a fix that exits from loadForRun instead of choosing one.
func TestPR99Round4StartupCollisionDoesNotDisableShippedRule(t *testing.T) {
	const entered = "PR99_ROUND4_ENTERED_LOAD_FOR_RUN"
	const unsafeExit = 86
	if dir := os.Getenv("ARGUS_PR99_ROUND4_STARTUP_DIR"); dir != "" {
		fmt.Fprintln(os.Stdout, entered)
		rs, _ := loadForRun(dir)
		for _, r := range rs {
			if r.ID == os.Getenv("ARGUS_PR99_ROUND4_STARTUP_ID") && r.File == os.Getenv("ARGUS_PR99_ROUND4_STARTUP_FILE") {
				os.Exit(0)
			}
		}
		fmt.Fprintln(os.Stdout, "startup returned a runnable snapshot without the shipped detector")
		os.Exit(unsafeExit)
	}

	for _, file := range []string{"host-ssh-bruteforce.yml", "ops/rules-rejected.yml"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", filepath.FromSlash(file)))
			if err != nil {
				t.Fatal(err)
			}
			dir := rulesDirWith(t, map[string]string{
				"unrelated.yml": "title: Unrelated\nid: pr99-round4-unrelated\ndetection:\n  selection: {action: other.event}\n",
			})
			path := filepath.Join(dir, filepath.FromSlash(file))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			rs, err := rules.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			var protected *rules.Rule
			for _, r := range rs {
				if r.File == file {
					protected = r
				}
			}
			if protected == nil {
				t.Fatal("fixture did not load the shipped detector")
			}
			e := &engine{rulesDir: dir, rulesSig: signature(dir)}
			e.rules.Store(&rs)
			duplicate := "title: Duplicate addition\nid: " + protected.ID + "\nlevel: low\ndetection:\n  selection: {action: unrelated.fixture}\n"
			// Sort after the original: before this delta the original also
			// remained first for ruleFor, so this is not the old shadowing bug.
			if err := os.WriteFile(filepath.Join(dir, "zz-duplicate.yml"), []byte(duplicate), 0o600); err != nil {
				t.Fatal(err)
			}
			if rejected := e.maybeReload(true); len(rejected) != 1 || rejected[0].File != "zz-duplicate.yml" || rejected[0].Reason != "duplicate_id" {
				t.Fatalf("live reload must reject only the newcomer: %+v", rejected)
			}
			if got := e.ruleFor(protected.ID); got == nil || got.File != file || got.Title != protected.Title || got.Level != protected.Level {
				t.Fatalf("live reload lost the authoritative detector: %+v", got)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPR99Round4StartupCollisionDoesNotDisableShippedRule$", "-test.timeout=8s")
			cmd.Env = []string{
				"PATH=/usr/bin:/bin", "TMPDIR=" + t.TempDir(),
				"ARGUS_PR99_ROUND4_STARTUP_DIR=" + dir,
				"ARGUS_PR99_ROUND4_STARTUP_ID=" + protected.ID,
				"ARGUS_PR99_ROUND4_STARTUP_FILE=" + file,
			}
			output, err := cmd.CombinedOutput()
			if !strings.Contains(string(output), entered) {
				t.Fatalf("startup probe did not reach loadForRun: err=%v\n%s", err, output)
			}
			if err == nil {
				return // An authoritative detector survived startup.
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
				return // Refusing ambiguous startup is also safe.
			}
			if errors.As(err, &exitErr) && exitErr.ExitCode() == unsafeExit {
				t.Fatalf("adding zz-duplicate.yml disables shipped %s after restart; loadForRun continues without it:\n%s", protected.ID, output)
			}
			t.Fatalf("unexpected startup probe failure: %v\n%s", err, output)
		})
	}
}
