package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

const pr99ReloadRule = "title: Previous rules\nid: pr99-reload\ndetection:\n  selection: {action: test.failure}\n  group_by: attrs.peer\n"

// No server, database, workers, or external calls are needed for reload and its
// observability. Exercise the real handler through the existing recorder helper.
func pr99ReloadFixture(t *testing.T) (*engine, *bytes.Buffer) {
	t.Helper()
	dir := rulesDirWith(t, map[string]string{"custom.yml": pr99ReloadRule})
	rs, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{
		rulesDir: dir, rulesSig: signature(dir), token: "fixture", mtoken: "fixture",
		resp: respond.New(respond.Config{Mode: respond.ModeIDS, ManualTTL: "1h"}),
	}
	e.rules.Store(&rs)
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	return e, &logs
}

func pr99WriteUnsupportedRule(t *testing.T, e *engine) {
	t.Helper()
	// Model a newer mounted rule arriving before its compatible engine image.
	next := strings.Replace(pr99ReloadRule, "Previous rules", "New rules", 1) + "  group_by_next: attrs.peer\n"
	if err := os.WriteFile(filepath.Join(e.rulesDir, "custom.yml"), []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPR99RejectedReloadReportsFailureToCaller(t *testing.T) {
	e, logs := pr99ReloadFixture(t)
	previous := e.current()[0]
	pr99WriteUnsupportedRule(t, e)
	code, body := do(t, e.handler(), http.MethodPost, "/reload", "fixture", "")
	if len(e.current()) != 1 || e.current()[0] != previous || e.m.reloads.Load() != 0 {
		t.Fatal("rejected reload must preserve the complete previous rule set")
	}
	for _, detail := range []string{"custom.yml", "line ", "group_by_next", "оставляю прежний набор"} {
		if !strings.Contains(logs.String(), detail) {
			t.Fatalf("missing actionable log diagnostic %q: %s", detail, logs.String())
		}
	}
	if code >= 200 && code < 300 {
		t.Errorf("reload was rejected but API reports success: HTTP %d %q", code, body)
	}
	if !strings.Contains(body, "custom.yml") || !strings.Contains(body, "group_by_next") {
		t.Errorf("reload caller cannot identify the rejected rule/field: HTTP %d %q", code, body)
	}
}

func TestPR99RejectedAutomaticReloadChangesTelemetry(t *testing.T) {
	e, _ := pr99ReloadFixture(t)
	h := e.handler()
	code, before := do(t, h, http.MethodGet, "/metrics", "fixture", "")
	if code != http.StatusOK {
		t.Fatalf("metrics fixture: HTTP %d %s", code, before)
	}
	pr99WriteUnsupportedRule(t, e)
	e.maybeReload(false)
	if e.current()[0].Title != "Previous rules" || e.m.reloads.Load() != 0 {
		t.Fatal("invalid rules must not be applied or counted as a successful reload")
	}
	code, after := do(t, h, http.MethodGet, "/metrics", "fixture", "")
	if code != http.StatusOK {
		t.Fatalf("metrics after failure: HTTP %d %s", code, after)
	}
	// No event processing or other activity occurs between these scrapes. A
	// failed reload must expose a changed counter/gauge without prescribing its
	// name. The successful-reload counter above must remain unchanged.
	if after == before {
		t.Fatal("Prometheus cannot distinguish a rejected rules update from a healthy unchanged rule set; no reload failure metric changes")
	}
}
