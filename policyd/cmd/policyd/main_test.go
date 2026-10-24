package main

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/policy"
	"github.com/devitex-soft/argus/policyd/internal/store"
)

func TestRoundTimeoutScalesWithAgents(t *testing.T) {
	cases := []struct {
		poll, perAgent time.Duration
		agents         int
		want           time.Duration
	}{
		{5 * time.Minute, 5 * time.Second, 0, 5 * time.Minute},      // без агентов — база
		{time.Minute, 5 * time.Second, 10, 2 * time.Minute},         // минимум 2 мин
		{5 * time.Minute, 5 * time.Second, 10, 5 * time.Minute},     // интервал больше
		{5 * time.Minute, 5 * time.Second, 200, 1000 * time.Second}, // парк большой — растёт
	}
	for _, c := range cases {
		if got := roundTimeout(c.poll, c.perAgent, c.agents); got != c.want {
			t.Errorf("roundTimeout(%v,%v,%d)=%v want %v", c.poll, c.perAgent, c.agents, got, c.want)
		}
	}
}

func TestPerAgentBudgetEnvPrefersNewNameThenLegacy(t *testing.T) {
	env := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		name      string
		env       map[string]string
		wantName  string
		wantValue string
	}{
		{"default", nil, perAgentEnv, "5s"},
		{"new", map[string]string{perAgentEnv: "7s"}, perAgentEnv, "7s"},
		{"legacy", map[string]string{legacyPerAgentEnv: "9s"}, legacyPerAgentEnv, "9s"},
		{"both → new wins", map[string]string{perAgentEnv: "7s", legacyPerAgentEnv: "9s"}, perAgentEnv, "7s"},
	}
	for _, c := range cases {
		name, value := perAgentBudgetEnv(env(c.env))
		if name != c.wantName || value != c.wantValue {
			t.Errorf("%s: got %s=%s, want %s=%s", c.name, name, value, c.wantName, c.wantValue)
		}
	}
}

func TestVerdictRowStatus(t *testing.T) {
	pass := verdictRow("s", "agent", "001", "a", "wazuh/agent", policy.Verdict{Compliant: true})
	if pass.Status != store.StatusPass || pass.Compliant != 1 || len(pass.Violations) != 0 {
		t.Fatalf("pass row: %+v", pass)
	}
	fail := verdictRow("s", "agent", "001", "a", "wazuh/agent", policy.Verdict{Violations: []string{"x"}})
	if fail.Status != store.StatusFail || fail.Compliant != 0 {
		t.Fatalf("fail row: %+v", fail)
	}
	unk := unknownRow("s", "sca", "001", "a", "wazuh/sca", "SCA fetch failed: timeout")
	if unk.Status != store.StatusUnknown || unk.Compliant != 0 || unk.Violations[0] != "SCA fetch failed: timeout" {
		t.Fatalf("unknown row: %+v", unk)
	}
}
