package main

// Регрессии PR #111: CLI должен проверять тот набор, который запускает run,
// а встроенные тесты поставляемых правил должны находить фикстуры в образе.
// Запуск: cd engine && go test ./cmd/engine -run '^TestPR111' -count=1

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// main вызывает os.Exit для rules test, поэтому настоящий CLI выполняется
// в дочернем тестовом процессе. Сервисы и сборка отдельного бинарника не нужны.
func TestPR111RulesCLIHelper(t *testing.T) {
	if os.Getenv("ARGUS_PR111_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			main()
			return
		}
	}
	t.Fatal("CLI helper requires -- before engine arguments")
}

func pr111RulesCLI(t *testing.T, shipped, user string, args ...string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestPR111RulesCLIHelper$", "--"}, args...)...)
	scratch := t.TempDir()
	cmd.Env = []string{
		"ARGUS_PR111_CLI_HELPER=1",
		"RULES_DIR=" + shipped,
		"RULES_USER_DIR=" + user,
		"HOME=" + scratch,
		"TMPDIR=" + scratch,
		"TZ=UTC",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("engine %v: %v (deadline: %v)\n%s", args, err, ctx.Err(), out)
	}
	return string(out)
}

func TestPR111RulesTestReplayIncludesConfiguredUserRules(t *testing.T) {
	shipped := rulesDirWith(t, map[string]string{"shipped.yml": simpleRule("qa-pr111-shipped", "shipped.action")})
	user := rulesDirWith(t, map[string]string{"custom.yml": simpleRule("qa-pr111-custom", "custom.action")})
	fixture := filepath.Join(t.TempDir(), "events.ndjson")
	if err := os.WriteFile(fixture, []byte(`{"ts":"2026-11-04 12:00:00.000","source":"qa","action":"custom.action","actor_name":"qa-actor"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Контроль: main знает пользовательский каталог, и list показывает правило.
	listed := pr111RulesCLI(t, shipped, user, "rules", "list")
	if !strings.Contains(listed, "qa-pr111-custom") {
		t.Fatalf("configured user rule is absent from rules list:\n%s", listed)
	}

	// Явный --dir по-прежнему позволяет отдельно проверять checkout.
	isolate := pr111RulesCLI(t, shipped, user, "rules", "test", "--dir", shipped, "--replay", fixture)
	if strings.Contains(isolate, "qa-pr111-custom") {
		t.Fatalf("explicit --dir unexpectedly includes the user catalogue:\n%s", isolate)
	}

	replayed := pr111RulesCLI(t, shipped, user, "rules", "test", "--replay", fixture)
	if !strings.Contains(replayed, "qa-pr111-custom") || !strings.Contains(replayed, "1 сработок") {
		t.Fatalf("default rules test must replay the configured user rule shown by list; it silently tests only shipped rules:\n%s", replayed)
	}
}

func TestPR111ImageRulesTestFindsPackagedFixtures(t *testing.T) {
	// Материализуем только локальные COPY правил/фикстур из настоящего
	// Dockerfile. Docker daemon и полный образ для проверки путей не нужны.
	repo, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(repo, "engine", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	imageRoot := t.TempDir()
	var rulesPath string
	copiedRules, copiedFixtures := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "ENV" {
			for _, field := range fields[1:] {
				if value, ok := strings.CutPrefix(field, "RULES_DIR="); ok {
					rulesPath = value
				}
			}
		}
		if len(fields) != 3 || fields[0] != "COPY" {
			continue
		}
		source, destination := fields[1], fields[2]
		isRules := source == "rules/"
		isFixtures := source == "fixtures/" || source == "fixtures/events/"
		if !isRules && !isFixtures {
			continue
		}
		if !filepath.IsAbs(destination) || strings.Contains(destination, "..") {
			t.Fatalf("unsupported COPY destination: %q", destination)
		}
		target := filepath.Join(imageRoot, filepath.FromSlash(strings.TrimPrefix(destination, "/")))
		if err := os.CopyFS(target, os.DirFS(filepath.Join(repo, source))); err != nil {
			t.Fatalf("COPY %s %s: %v", source, destination, err)
		}
		copiedRules = copiedRules || isRules
		copiedFixtures = copiedFixtures || isFixtures
	}
	if !copiedRules || !copiedFixtures || !filepath.IsAbs(rulesPath) || strings.Contains(rulesPath, "..") {
		t.Fatalf("cannot materialize image layout: rules=%v fixtures=%v RULES_DIR=%q", copiedRules, copiedFixtures, rulesPath)
	}
	rulesDir := filepath.Join(imageRoot, filepath.FromSlash(strings.TrimPrefix(rulesPath, "/")))
	tests, err := filepath.Glob(filepath.Join(rulesDir, "tests", "*.yml"))
	if err != nil || len(tests) == 0 {
		t.Fatalf("image fixture must include shipped rule tests: %v, count=%d", err, len(tests))
	}
	if code := rulesTest(rulesDir, nil); code != 0 {
		t.Fatalf("engine rules test fails in the image layout (exit %d): test fixtures reference fixtures/events/, but COPY removes the events/ component", code)
	}
}
