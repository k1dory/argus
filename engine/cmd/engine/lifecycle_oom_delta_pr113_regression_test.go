package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/respond"
)

// memory.events contains cumulative counters. A surviving cgroup with an old
// oom_kill must not turn every later panic/SIGKILL restart into another OOM.
func TestPR113RestartReasonRequiresANewOOMKill(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kills  int
		reason string
	}{
		{name: "unchanged_counter_after_unclean_exit", kills: 7, reason: "unclean"},
		{name: "new_oom_kill", kills: 8, reason: "oom"},
		{name: "recreated_cgroup", kills: 0, reason: "unclean"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCH(t)
			const query = "action IN ('engine.started', 'engine.stopped')"
			f.mu.Lock()
			f.selects[query] = `{"action":"engine.stopped","at":"2026-11-04 11:59:00.000"}`
			f.mu.Unlock()
			dir := rulesDirWith(t, map[string]string{"r.yml": capRule(4)})
			counter := filepath.Join(t.TempDir(), "memory.events")
			if err := os.WriteFile(counter, []byte("oom_kill 7\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			start := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
			previous := testEngine(t, f, dir, respond.Config{}, "dummy-engine", "dummy-metrics")
			previous.cgroupEvents = counter
			previous.announceStart(context.Background(), start)
			started, ok := lifecycleRows(t, f)["engine.started"]
			if !ok {
				t.Fatal("fixture: previous run did not persist engine.started")
			}
			// Return the previous start and any counter snapshot it persisted.
			row, err := json.Marshal(map[string]any{
				"action": started.Action, "at": started.TS,
				"attrs": started.Attrs, "oom_kill": started.Attrs["oom_kill"],
			})
			if err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			f.selects[query] = string(row)
			f.mu.Unlock()
			if err := os.WriteFile(counter, []byte(fmt.Sprintf("oom_kill %d\n", tc.kills)), 0o600); err != nil {
				t.Fatal(err)
			}
			// No announceStop: the previous process exited abnormally.
			next := testEngine(t, f, dir, respond.Config{}, "dummy-engine", "dummy-metrics")
			next.cgroupEvents = counter
			next.announceStart(context.Background(), start.Add(time.Minute))
			restarted, ok := lifecycleRows(t, f)["engine.restarted"]
			if !ok || next.m.uncleanRestarts.Load() != 1 {
				t.Fatal("fixture: unclean restart must be recorded and counted")
			}
			if got := restarted.Attrs["reason"]; got != tc.reason {
				t.Fatalf("oom_kill 7 -> %d: reason=%q, want %q; an old OOM is not evidence of this exit", tc.kills, got, tc.reason)
			}
		})
	}
}
