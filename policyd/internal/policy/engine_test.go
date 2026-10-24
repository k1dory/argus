package policy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The test evaluates the real policies from ../../../policies through the
// embedded OPA engine, so `go test ./...` covers the Rego code even when the
// opa binary is not installed.
func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := New(context.Background(), "../../../policies", []string{"agent", "sca"})
	if err != nil {
		t.Fatalf("load policies: %v", err)
	}
	return e
}

func TestAgentPolicy(t *testing.T) {
	e := newTestEngine(t)
	fresh := map[string]any{
		"id": "001", "name": "web-01", "status": "active",
		"version": "Wazuh v4.12.0", "stale_seconds": 30, "os_platform": "ubuntu",
	}

	v, err := e.Eval(context.Background(), "agent", fresh)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Compliant || len(v.Violations) != 0 {
		t.Fatalf("fresh agent must be compliant, got %+v", v)
	}

	stale := map[string]any{
		"id": "002", "name": "db-01", "status": "disconnected",
		"version": "Wazuh v4.2.0", "stale_seconds": 90000, "os_platform": "centos",
	}
	v, err = e.Eval(context.Background(), "agent", stale)
	if err != nil {
		t.Fatal(err)
	}
	if v.Compliant || len(v.Violations) != 2 {
		t.Fatalf("stale old agent must have 2 violations (status, version), got %+v", v)
	}
}

func TestSCAPolicy(t *testing.T) {
	e := newTestEngine(t)
	v, err := e.Eval(context.Background(), "sca", map[string]any{
		"agent_id": "001", "agent_name": "web-01",
		"policy": "CIS Ubuntu 22.04 Benchmark", "policy_id": "cis_ubuntu22-04",
		"score": 40, "pass": 80, "fail": 120, "invalid": 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Compliant || len(v.Violations) != 2 {
		t.Fatalf("low score + invalid checks must give 2 violations, got %+v", v)
	}
}

func TestUnknownPackage(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.Eval(context.Background(), "nope", nil); err == nil {
		t.Fatal("expected error for unknown policy package")
	}
}

// engineWithConfig копирует политики (без *_test.rego) во временный каталог и
// подменяет config.json — так проверяются пороги неверного типа.
func engineWithConfig(t *testing.T, config string) *Engine {
	t.Helper()
	dir := t.TempDir()
	entries, err := os.ReadDir("../../../policies")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".rego") || strings.HasSuffix(name, "_test.rego") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("../../../policies", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := New(context.Background(), dir, []string{"agent", "sca"})
	if err != nil {
		t.Fatalf("load policies with config %s: %v", config, err)
	}
	return e
}

func hasPrefix(vs []string, prefix string) bool {
	for _, v := range vs {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}

func TestSCAStringThresholdIsConfigError(t *testing.T) {
	e := engineWithConfig(t, `{"config":{"sca":{"min_score":"75"}}}`)
	v, err := e.Eval(context.Background(), "sca", map[string]any{
		"policy": "CIS", "policy_id": "cis", "score": 91, "pass": 1, "fail": 0, "invalid": 0,
	})
	if err != nil {
		t.Fatalf("string threshold must not break eval: %v", err)
	}
	if v.Compliant || !hasPrefix(v.Violations, "policy config invalid") {
		t.Fatalf("string threshold must be reported as config error, got %+v", v)
	}
}

func TestAgentStringThresholdIsConfigError(t *testing.T) {
	e := engineWithConfig(t, `{"config":{"agent":{"max_stale_seconds":"600","min_version":4.9}}}`)
	v, err := e.Eval(context.Background(), "agent", map[string]any{
		"id": "001", "status": "active", "version": "Wazuh v4.12.0", "stale_seconds": 30,
	})
	if err != nil {
		t.Fatalf("string threshold must not break eval: %v", err)
	}
	if v.Compliant || !hasPrefix(v.Violations, "policy config invalid") {
		t.Fatalf("expected config error, got %+v", v)
	}
}

func TestSCAMissingScoreViolates(t *testing.T) {
	e := newTestEngine(t)
	v, err := e.Eval(context.Background(), "sca", map[string]any{
		"policy": "CIS", "policy_id": "cis", "pass": 1, "fail": 0, "invalid": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if v.Compliant || len(v.Violations) != 1 {
		t.Fatalf("missing score must be one violation, got %+v", v)
	}
}

func TestEmptyInputIsNotCompliant(t *testing.T) {
	e := newTestEngine(t)
	for _, pkg := range []string{"agent", "sca"} {
		v, err := e.Eval(context.Background(), pkg, map[string]any{})
		if err != nil {
			t.Fatalf("%s: empty input must not break eval: %v", pkg, err)
		}
		if v.Compliant || len(v.Violations) == 0 {
			t.Fatalf("%s: empty input must not be compliant, got %+v", pkg, v)
		}
	}
	// nil input — тоже не ошибка и не «соответствует».
	v, err := e.Eval(context.Background(), "sca", nil)
	if err != nil || v.Compliant {
		t.Fatalf("nil input: err=%v verdict=%+v", err, v)
	}
}
