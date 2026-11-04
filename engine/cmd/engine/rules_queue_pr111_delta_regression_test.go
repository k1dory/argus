package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// Valid user files colliding with a shipped ID are rejected individually.
// They must not evict an unrelated shipped rejection from the shared event
// queue. Use only 1000 tiny files and the in-process sink from the recovery
// test; no live service or external connection is involved.
func TestPR111DeltaUserRejectionsCannotEvictShippedRejection(t *testing.T) {
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	for _, phase := range []string{"startup", "reload"} {
		t.Run(phase, func(t *testing.T) {
			sink := pr111DeltaInstallRulesEventSink(t)
			protected := simpleRule("pr111-queue-protected", "protected.action")
			good := simpleRule("pr111-queue-pending", "pending.action")
			bad := good + "  group_by_next: attrs.peer\n"
			collisions := map[string]string{}
			for i := 0; i < 1000; i++ {
				collisions[fmt.Sprintf("collision-%04d.yml", i)] = simpleRule("pr111-queue-protected", "override.action")
			}
			shippedFiles := map[string]string{"protected.yml": protected, "pending.yml": good}
			userFiles := map[string]string{}
			if phase == "startup" {
				shippedFiles["pending.yml"], userFiles = bad, collisions
			}
			e := pr111DeltaRulesEngine(t, shippedFiles, userFiles)
			if phase == "reload" {
				if err := os.WriteFile(filepath.Join(e.dirs.shipped, "pending.yml"), []byte(bad), 0o600); err != nil {
					t.Fatal(err)
				}
				for path, raw := range collisions {
					if err := os.WriteFile(filepath.Join(e.dirs.user, path), []byte(raw), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				e.maybeReload(true)
			}
			const object = "shipped/pending.yml"
			if !e.rulesBad[object] || e.m.rulesRejected.Load() != 1001 {
				t.Fatalf("fixture must reject one shipped and 1000 user files: shippedBad=%v gauge=%d", e.rulesBad[object], e.m.rulesRejected.Load())
			}
			if r := e.ruleFor("pr111-queue-protected"); r == nil || r.User || r.Detection.Selection["action"] != "protected.action" {
				t.Fatalf("control: shipped detector was replaced: %+v", r)
			}
			for tick := 0; tick < 3; tick++ {
				e.maybeReload(false)
				e.flushRulesEvents(context.Background())
				pr111DeltaApplyRulesEvents(e, sink.events)
			}
			for _, key := range e.reg.OpenGroupKeys("a41c-ops-068") {
				if key == object {
					return
				}
			}
			t.Fatalf("%s: 1000 rejected user files hid %s from the shipped ops detector; delivered events=%d, rejection gauge=%d", phase, object, len(sink.events), e.m.rulesRejected.Load())
		})
	}
}
