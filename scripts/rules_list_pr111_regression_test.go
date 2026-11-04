package scripts_test

// Регрессия PR #111: настройки для тестирования checkout не должны менять
// набор, показываемый rules list на хосте без Go.
// Запуск: go test -count=1 ./scripts/rules_list_pr111_regression_test.go
// Исполняется настоящий scripts/argus; вместо Docker — локальная запись argv.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func pr111WrapperDockerArgs(t *testing.T, command string) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("scripts/argus requires Bash and POSIX tools")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	dirname, err := exec.LookPath("dirname")
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate scripts/argus")
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(source), "argus"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{bin, filepath.Join(root, "scripts"), filepath.Join(root, "rules.d")} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "scripts", "argus"), string(script), 0o700)
	write(filepath.Join(root, ".env"), "ARGUS_USER_RULES_DIR="+filepath.Join(root, "rules.d")+"\n", 0o600)
	write(filepath.Join(bin, "docker"), "#!/bin/sh\nprintf '%s\\n' \"$@\" >\"$ARGUS_PR111_DOCKER_ARGS\"\n", 0o700)
	if err := os.Symlink(dirname, filepath.Join(bin, "dirname")); err != nil {
		t.Fatal(err)
	}
	trace := filepath.Join(root, "docker-args")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, filepath.Join(root, "scripts", "argus"), "rules", command)
	// В PATH намеренно нет Go: проверяем типичный прод-хост с Docker.
	cmd.Env = []string{"PATH=" + bin, "HOME=" + root, "TMPDIR=" + root, "ARGUS_PR111_DOCKER_ARGS=" + trace}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("argus rules %s: %v\n%s", command, err, out)
	}
	out, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
}

func TestPR111RulesListPreservesConfiguredCatalogues(t *testing.T) {
	args := pr111WrapperDockerArgs(t, "list")
	for i, arg := range args {
		if arg != "-e" || i+1 >= len(args) {
			continue
		}
		switch args[i+1] {
		case "RULES_USER_DIR=":
			t.Error("rules list disables RULES_USER_DIR even though the engine service loads that catalogue")
		case "RULES_DIR=/rules":
			t.Error("rules list replaces the shipped image catalogue with checkout rules; its output can differ from the running service")
		}
	}
}

func TestPR111RulesTestStillSelectsCheckout(t *testing.T) {
	args := pr111WrapperDockerArgs(t, "test")
	for i, arg := range args {
		if arg == "-e" && i+1 < len(args) && args[i+1] == "RULES_DIR=/rules" {
			return
		}
	}
	t.Fatal("rules test must retain the documented checkout workflow")
}
