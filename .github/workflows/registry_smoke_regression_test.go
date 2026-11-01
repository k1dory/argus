package workflows_test

// PR #73: engine is distroless and receives /bin/busybox only, without its
// applet links. Official busybox:1.37-musl uses make defconfig, whose shell
// standalone mode is disabled (https://busybox.net/FAQ.html).
// Exercise the actual CI shell snippet with the same command lookup contract:
// busybox is available, but a bare ls is not. No Docker daemon is used.
// Run from the repo root in isolation:
//   go test ./.github/workflows/registry_smoke_regression_test.go -count=1

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestRegistrySmokeWorksWithoutAppletLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("CI runs a POSIX shell on Linux")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	ls, err := exec.LookPath("ls")
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate ci.yml")
	}
	workflow, err := os.ReadFile(filepath.Join(filepath.Dir(source), "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^\s*docker run[^\n]*argus-ci/engine:check sh -c '([^'\n]*)'\s*$`)
	match := re.FindStringSubmatch(string(workflow))
	if len(match) != 2 {
		t.Fatal("engine registry shell probe not found in ci.yml; update this harness if its invocation changes")
	}

	scratch := t.TempDir()
	bin := filepath.Join(scratch, "bin")
	shipped := filepath.Join(scratch, "shipped")
	for _, dir := range []string{bin, filepath.Join(shipped, "fixtures"), filepath.Join(scratch, "home"), filepath.Join(scratch, "tmp")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixture := filepath.Join(shipped, "fixtures", "events.ndjson")
	if err := os.WriteFile(fixture, []byte("{\"source\":\"qa\",\"action\":\"qa\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A multicall stand-in permits explicit busybox ls but deliberately does
	// not install an ls executable into PATH, matching engine/Dockerfile.
	busybox := filepath.Join(bin, "busybox")
	shim := "#!" + sh + "\ncase \"$1\" in\nls) shift; exec " + registrySmokeQuote(ls) + " \"$@\" ;;\n*) exit 125 ;;\nesac\n"
	if err := os.WriteFile(busybox, []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}
	run := func(script string) (string, error) {
		script = strings.NewReplacer(
			"/usr/share/argus/shipped", registrySmokeQuote(shipped),
			"/bin/busybox", registrySmokeQuote(busybox),
		).Replace(script)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, sh, "-c", script)
		cmd.Dir = scratch
		cmd.Env = []string{"PATH=" + bin, "HOME=" + filepath.Join(scratch, "home"),
			"TMPDIR=" + filepath.Join(scratch, "tmp"), "LC_ALL=C", "TZ=UTC"}
		cmd.WaitDelay = time.Second
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	// Positive control proves the fixture is accessible through the explicit
	// multicall executable before running the workflow's unchanged snippet.
	if out, err := run("/bin/busybox ls /usr/share/argus/shipped/fixtures/*.ndjson >/dev/null"); err != nil {
		t.Fatalf("harness control failed: %v\n%s", err, out)
	}
	if out, err := run(match[1]); err != nil {
		t.Errorf("CI rejects a complete fixture bundle when only busybox is installed: %v\n%s", err, out)
	}
	if err := os.Remove(fixture); err != nil {
		t.Fatal(err)
	}
	if out, err := run(match[1]); err == nil {
		t.Errorf("CI probe accepted an image without fixtures: %s", out)
	}
}

func registrySmokeQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
