package scripts_test

// PR #68: failure diagnostics must retain useful evidence without publishing
// ClickHouse password verifiers. Run this file on its own (stdlib only):
//
//   go test -count=1 ./scripts/e2e_failure_regression_test.go
//
// The real e2e.sh runs in a disposable checkout with a fake Docker CLI and a
// no-op sample generator. No Docker daemon, image, network or credentials are
// needed. Run in an isolated environment, as for other script tests.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	e2eDummyPassword = "qa-only-e2e-password-never-used"
	e2eDummySalt     = "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c"
	e2eInspectOnly   = "qa-only-env-canary-not-part-of-state"
	e2eHealthOutput  = "qa-only-health-probe-connection-refused"
	e2eServerLog     = "qa-only-clickhouse-startup-diagnostic"
)

type e2eFailureResult struct {
	stdout, stderr string
	exitCode       int
	calls          [][]string
}

func runE2EFailure(t *testing.T, buildx bool, failLookup bool) e2eFailureResult {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("e2e.sh requires Bash and POSIX tools")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate scripts/e2e.sh")
	}
	script, err := os.ReadFile(filepath.Join(filepath.Dir(source), "e2e.sh"))
	if err != nil {
		t.Fatal(err)
	}
	scratch := t.TempDir()
	root := filepath.Join(scratch, "checkout with spaces")
	bin := filepath.Join(scratch, "bin")
	for _, dir := range []string{filepath.Join(root, "scripts"), bin, filepath.Join(scratch, "home"), filepath.Join(scratch, "tmp")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name string, body []byte) {
		t.Helper()
		if err := os.WriteFile(name, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "scripts", "e2e.sh"), script)
	write(filepath.Join(root, "scripts", "gen-sample.sh"), []byte("#!/bin/sh\nexit 0\n"))
	write(filepath.Join(bin, "docker"), []byte(e2eFakeDocker))
	callsFile := filepath.Join(scratch, "docker-calls.tsv")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, filepath.Join(root, "scripts", "e2e.sh"))
	cmd.Dir = root
	// Do not inherit shell startup files, Docker contexts, proxies or secrets.
	// An exported password can override --env-file .env.dev in real Compose.
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + "/usr/bin:/bin",
		"HOME=" + filepath.Join(scratch, "home"),
		"TMPDIR=" + filepath.Join(scratch, "tmp"), "LC_ALL=C", "TZ=UTC",
		"DOCKER_HOST=unix://" + filepath.Join(scratch, "no-daemon.sock"),
		"CLICKHOUSE_CONSOLE_PASSWORD=" + e2eDummyPassword,
		fmt.Sprintf("ARGUS_E2E_QA_VERIFIER=%x", sha256.Sum256([]byte(e2eDummyPassword+e2eDummySalt))),
		"ARGUS_E2E_QA_SALT=" + e2eDummySalt,
		"ARGUS_E2E_QA_CONFIG_SECRET=" + e2eInspectOnly,
		"ARGUS_E2E_QA_HEALTH_OUTPUT=" + e2eHealthOutput,
		"ARGUS_E2E_QA_SERVER_LOG=" + e2eServerLog,
		"ARGUS_E2E_QA_CALLS=" + callsFile,
		fmt.Sprintf("ARGUS_E2E_QA_BUILDX=%t", buildx),
		fmt.Sprintf("ARGUS_E2E_QA_FAIL_LOOKUP=%t", failLookup),
	}
	cmd.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("e2e failure handler timed out: %v", ctx.Err())
	}
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatalf("cannot run e2e.sh: %v", err)
	}
	result := e2eFailureResult{stdout: stdout.String(), stderr: stderr.String(), exitCode: cmd.ProcessState.ExitCode()}
	raw, err := os.ReadFile(callsFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		result.calls = append(result.calls, strings.Split(strings.TrimRight(line, "\t"), "\t"))
	}
	if result.exitCode == 0 {
		t.Fatal("a failed compose up must fail e2e.sh")
	}
	if strings.Contains(result.stderr, "unexpected fake Docker call") {
		t.Fatalf("fixture did not model an invocation: %s", result.stderr)
	}
	if !strings.Contains(result.stderr, "error: стенд e2e не поднялся") {
		t.Fatalf("failure handler was not reached: %s", result.stderr)
	}
	if !slices.ContainsFunc(result.calls, func(args []string) bool {
		return slices.Equal(args, []string{"compose", "--profile", "mcp", "down", "-v", "--remove-orphans"})
	}) {
		t.Fatal("the EXIT trap did not clean up the disposable stack")
	}
	return result
}

func TestE2EFailureDiagnosticsDoNotExposePasswordVerifier(t *testing.T) {
	// migrate.sh supplies sha256(password + salt) to CREATE/ALTER USER.
	// ClickHouse 24.8 prints the original query on error, including both values:
	// https://github.com/ClickHouse/ClickHouse/blob/v24.8.14.39-lts/programs/client/Client.cpp#L67-L100
	// The fixture models a failed ALTER after CREATE succeeded (e.g. disk full).
	verifier := fmt.Sprintf("%x", sha256.Sum256([]byte(e2eDummyPassword+e2eDummySalt)))
	for _, buildx := range []bool{true, false} {
		t.Run(fmt.Sprintf("buildx=%t", buildx), func(t *testing.T) {
			result := runE2EFailure(t, buildx, false)
			output := result.stdout + result.stderr
			for _, secret := range []string{e2eDummyPassword, verifier, e2eDummySalt} {
				if strings.Contains(output, secret) {
					t.Error("failure diagnostics disclose password material from the migrator log")
				}
			}
			if !strings.Contains(result.stderr, e2eHealthOutput) {
				t.Error("non-secret health history should remain available")
			}
		})
	}
}

func TestE2EFailureDiagnosticsSurviveClickHouseLookupError(t *testing.T) {
	for _, buildx := range []bool{true, false} {
		t.Run(fmt.Sprintf("buildx=%t", buildx), func(t *testing.T) {
			// Only the container-ID lookup fails. Later log reads would succeed,
			// as after a transient daemon/API error; diagnostics must try them.
			result := runE2EFailure(t, buildx, true)
			if !strings.Contains(result.stderr, e2eServerLog) {
				t.Error("a failed container-ID lookup suppressed available ClickHouse logs")
			}
			if result.exitCode != 1 {
				t.Errorf("expected the e2e failure exit code 1, got the diagnostic command's exit code %d", result.exitCode)
			}
		})
	}
}

func TestE2EFailureDiagnosticsInspectStateWithoutEnvironment(t *testing.T) {
	// Control: narrowing inspect to .State retains Health.Log and excludes
	// Config.Env. Expanding inspect to the whole object must fail this check.
	for _, buildx := range []bool{true, false} {
		t.Run(fmt.Sprintf("buildx=%t", buildx), func(t *testing.T) {
			result := runE2EFailure(t, buildx, false)
			if !strings.Contains(result.stderr, e2eHealthOutput) {
				t.Error("Health.Log is missing from stderr")
			}
			if strings.Contains(result.stdout+result.stderr, e2eInspectOnly) {
				t.Error("inspect disclosed Config.Env")
			}
		})
	}
}

// A separate shell stub avoids re-entering the scripts package's TestMain.
// It never opens a socket or launches Docker. All output is synthetic.
const e2eFakeDocker = `#!/bin/sh
set -eu
if [ "$1" = compose ]; then
  shift
  while [ "$#" -ge 2 ]; do
    case "$1" in --env-file|-f) shift 2 ;; *) break ;; esac
  done
  set -- compose "$@"
fi
printf '%s\t' "$@" >>"$ARGUS_E2E_QA_CALLS"
printf '\n' >>"$ARGUS_E2E_QA_CALLS"
if [ "$*" = 'buildx version' ]; then
  [ "$ARGUS_E2E_QA_BUILDX" = true ]
  exit 0
fi
if [ "$1" = inspect ]; then
  state=$(printf '{"Status":"running","Health":{"Status":"healthy","Log":[{"ExitCode":1,"Output":"%s"}]}}' "$ARGUS_E2E_QA_HEALTH_OUTPUT")
  if [ "$#" = 4 ] && [ "$2" = --format ] && [ "$3" = '{{json .State}}' ] && [ "$4" = qa-clickhouse-id ]; then
    printf '%s\n' "$state"
  else
    printf '[{"State":%s,"Config":{"Env":["TOKEN=%s"]}}]\n' "$state" "$ARGUS_E2E_QA_CONFIG_SECRET"
  fi
  exit 0
fi
if [ "$1" = compose ]; then
  shift
  if [ "${1:-}" = --profile ] && [ "${2:-}" = mcp ]; then shift 2; fi
  case "$1" in
    up)
      echo 'service migrator did not complete successfully: exit 76' >&2
      exit 1 ;;
    ps)
      if [ "$*" = 'ps -aq clickhouse' ]; then
        if [ "$ARGUS_E2E_QA_FAIL_LOOKUP" = true ]; then
          echo 'temporary Docker API failure' >&2
          exit 125
        fi
        echo qa-clickhouse-id
        exit 0
      fi
      if [ "$*" = 'ps -a' ]; then
        printf 'NAME STATUS\nqa-clickhouse Up (healthy)\nqa-migrator Exited (76)\n'
        exit 0
      fi ;;
    logs)
      for service do :; done
      case "$service" in
        clickhouse) printf '%s\n' "$ARGUS_E2E_QA_SERVER_LOG"; exit 0 ;;
        migrator)
          printf "Received exception from server (version 24.8):\nCode: 76. DB::Exception: Cannot write access entity: No space left on device.\n(query: ALTER USER argus_console IDENTIFIED WITH sha256_hash BY '%s' SALT '%s')\n" "$ARGUS_E2E_QA_VERIFIER" "$ARGUS_E2E_QA_SALT"
          exit 0 ;;
      esac ;;
    down) exit 0 ;;
  esac
fi
echo "unexpected fake Docker call: $*" >&2
exit 91
`
