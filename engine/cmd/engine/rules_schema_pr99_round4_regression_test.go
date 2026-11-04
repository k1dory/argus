package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// The mixed-key schema bypass also bypasses fallback, the 422 response, the
// rejection gauge and the operational event. Exercise the real reload handler.
func TestPR99Round4MixedKeyReloadKeepsPreviousRuleAndReportsRejection(t *testing.T) {
	const good = "title: Protected\nid: pr99-round4-reload\ndetection:\n  selection: {action: test.failure}\n  group_by: attrs.peer\n"
	dir := rulesDirWith(t, map[string]string{"protected.yml": good})
	rs, err := rules.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{
		rulesDir: dir, rulesSig: signature(dir), token: "fixture", mtoken: "fixture",
		resp: respond.New(respond.Config{Mode: respond.ModeIDS, ManualTTL: "1h"}),
	}
	e.rules.Store(&rs)
	previous := rs[0]
	next := strings.Replace(good, "group_by: attrs.peer", "group_by: attrs.peer, attrs.source", 1) +
		"  group_by_next: attrs.peer\n  7: ignored\n"
	if err := os.WriteFile(filepath.Join(dir, "protected.yml"), []byte(next), 0o600); err != nil {
		t.Fatal(err)
	}
	code, body := do(t, e.handler(), http.MethodPost, "/reload", "fixture", "")
	if code != http.StatusUnprocessableEntity {
		t.Errorf("unsupported migration must return 422: HTTP %d %s", code, body)
	}
	if len(e.current()) != 1 || e.current()[0] != previous {
		t.Errorf("unsupported migration replaced the last valid rule: %+v", e.current())
	}
	if got := e.m.rulesRejected.Load(); got != 1 {
		t.Errorf("argus_engine_rules_rejected=%d, want 1", got)
	}
	if got := e.m.reloadFailures.Load(); got != 1 || e.m.reloads.Load() != 0 {
		t.Errorf("reload failure was reported as success: failures=%d successes=%d", got, e.m.reloads.Load())
	}
	if len(e.rulesPending) != 1 || e.rulesPending[0].Action != "rules.rejected" || e.rulesPending[0].Object != "protected.yml" {
		t.Errorf("missing operational rejection event: %+v", e.rulesPending)
	}
}
