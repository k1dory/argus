package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

func lifecycleRows(t *testing.T, f *fakeCH) map[string]model.Event {
	t.Helper()
	out := map[string]model.Event{}
	for _, line := range f.rows("events") {
		var ev model.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatal(err)
		}
		out[ev.Action] = ev
	}
	return out
}

// Старт после started без stopped — engine.restarted с причиной (oom, если cgroup
// насчитала oom_kill); после stopped или на первом запуске — только engine.started.
func TestAnnounceStartDetectsUncleanRestart(t *testing.T) {
	for _, tc := range []struct {
		name, last, oom, reason string
		restarted               bool
	}{
		{"oom", `{"action":"engine.started","at":"2026-11-02 19:38:00.000"}`, "low 0\noom 3\noom_kill 3\n", "oom", true},
		{"unclean", `{"action":"engine.started","at":"2026-11-02 19:38:00.000"}`, "oom_kill 0\n", "unclean", true},
		{"clean", `{"action":"engine.stopped","at":"2026-11-02 19:38:00.000"}`, "oom_kill 7\n", "", false},
		{"first_run", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeCH(t)
			f.mu.Lock()
			f.selects["action IN ('engine.started', 'engine.stopped')"] = tc.last + "\n"
			f.mu.Unlock()
			e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": capRule(4)}), respond.Config{}, "s", "s")
			e.cgroupEvents = filepath.Join(t.TempDir(), "memory.events")
			if tc.oom != "" {
				if err := os.WriteFile(e.cgroupEvents, []byte(tc.oom), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			e.announceStart(context.Background(), time.Now())
			f.waitRows(t, "events", 1)
			rows := lifecycleRows(t, f)
			started, ok := rows["engine.started"]
			if !ok || started.Attrs["transport"] != "internal" || started.Source != systemSource || started.Product != "engine" {
				t.Fatalf("engine.started: %+v", rows)
			}
			r, restarted := rows["engine.restarted"]
			if restarted != tc.restarted {
				t.Fatalf("engine.restarted = %v, ожидалось %v: %+v", restarted, tc.restarted, rows)
			}
			if restarted && (r.Attrs["reason"] != tc.reason || r.Attrs["previous_start"] == "" || e.m.uncleanRestarts.Load() != 1) {
				t.Fatalf("причина: %+v, счётчик %d", r.Attrs, e.m.uncleanRestarts.Load())
			}
		})
	}
}

func TestAnnounceStopWritesStopped(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": capRule(4)}), respond.Config{}, "s", "s")
	e.announceStop(time.Now())
	f.waitRows(t, "events", 1)
	if ev, ok := lifecycleRows(t, f)["engine.stopped"]; !ok || ev.Attrs["transport"] != "internal" {
		t.Fatal("engine.stopped не записан")
	}
}

// pprof — только с токеном метрик.
func TestPprofRequiresMetricsToken(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": capRule(4)}), respond.Config{}, "s", "m")
	srv := httptest.NewServer(e.pprofHandler())
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		token string
		want  int
	}{{"", http.StatusUnauthorized}, {"s", http.StatusUnauthorized}, {"m", http.StatusOK}} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/debug/pprof/heap", nil)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("токен %q: HTTP %d, ожидалось %d", tc.token, resp.StatusCode, tc.want)
		}
	}
}
