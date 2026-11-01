//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/sink"
)

const pr33ShutdownChildEnv = "ARGUS_PR33_STDERR_SHUTDOWN_CHILD"

// Both forced-exit paths must remain bounded when the log consumer stops
// reading stderr. Exercise the real main in a child: os.Exit must never kill
// the parent go test, and a child's t.Fatal must not count as the expected exit.
// Writable-stderr cases control for fixture failures and check the unfinished
// task diagnostic. Every case also checks replay of a previously accepted batch.
func TestPR33ForcedShutdownWithBlockedStderr(t *testing.T) {
	const ready = "pr33: pending spool insert started"
	const second = "pr33: sending second signal"
	const survived = "pr33: forced shutdown did not terminate the process"
	if scenario := os.Getenv(pr33ShutdownChildEnv); scenario != "" {
		pr33RunStderrShutdownChild(t, scenario, ready, second, survived)
		return
	}

	for _, trigger := range []string{"deadline", "sigterm", "sigint"} {
		for _, stderrMode := range []string{"writable", "blocked"} {
			t.Run(trigger+"/"+stderrMode, func(t *testing.T) {
				dir := t.TempDir()
				spoolDir := filepath.Join(dir, "spool")
				q, err := sink.NewDurableQueue(spoolDir, 1<<20, &sink.Stats{})
				if err != nil {
					t.Fatal(err)
				}
				const object = "accepted-before-forced-shutdown"
				if err := q.Push([]any{model.Event{Source: "pr33.stderr", Object: object}}); err != nil {
					t.Fatal(err)
				}
				q.Close()
				configPath := filepath.Join(dir, "collector.yml")
				// An invalid port fails locally without binding a socket or DNS.
				config := `listeners:
  syslog:
    udp: ""
    tcp: ""
  netflow:
    udp: ""
  http:
    addr: "127.0.0.1:65536"
    token: "pr33-fixture-token"
batch:
  pending_rows: 8
`
				if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
					t.Fatal(err)
				}
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, executable,
					"-test.run=^TestPR33ForcedShutdownWithBlockedStderr$",
					"-test.count=1", "-test.v", "-test.timeout=12s")
				timeout := "2s"
				if trigger != "deadline" {
					// A broken second-signal path cannot pass via the deadline.
					timeout = "1h"
				}
				cmd.Dir = dir
				cmd.Env = []string{
					pr33ShutdownChildEnv + "=" + trigger + "/" + stderrMode,
					"COLLECTOR_CONFIG=" + configPath,
					"SINK_SPOOL_DIR=" + spoolDir, "SINK_SPOOL_BYTES=1048576",
					"CLICKHOUSE_URL=http://clickhouse.invalid",
					"ARGUS_SHUTDOWN_TIMEOUT=" + timeout, "LOG_LEVEL=error",
					"TMPDIR=" + dir, "GOTRACEBACK=all",
				}
				cmd.WaitDelay = time.Second
				output, err := cmd.CombinedOutput()
				out := string(output)
				var exitErr *exec.ExitError
				if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 ||
					!strings.Contains(out, ready) || strings.Contains(out, survived) ||
					strings.Contains(out, "--- FAIL:") || strings.Contains(out, "WARNING: DATA RACE") {
					t.Fatalf("forced shutdown with %s stderr must exit 1 within its bound: %v\n%s", stderrMode, err, out)
				}
				if trigger != "deadline" && !strings.Contains(out, second) {
					t.Fatalf("the first signal interrupted the pending drain:\n%s", out)
				}
				if stderrMode == "writable" {
					message := "дренаж не уложился в ARGUS_SHUTDOWN_TIMEOUT"
					if trigger != "deadline" {
						message = "повторный сигнал"
					}
					reported := false
					for _, line := range strings.Split(out, "\n") {
						if strings.Contains(line, message) && strings.Contains(line, "unfinished=") && strings.Contains(line, "batcher") {
							reported = true
						}
					}
					if !reported {
						t.Errorf("forced exit did not report the pending batcher:\n%s", out)
					}
				}
				recovered, err := sink.NewDurableQueue(spoolDir, 1<<20, &sink.Stats{})
				if err != nil {
					t.Fatal(err)
				}
				defer recovered.Close()
				if recovered.Rows() != 1 {
					t.Fatalf("forced exit lost an accepted spool batch: rows=%d", recovered.Rows())
				}
				batch, ok := recovered.Pop()
				if !ok || len(batch.Rows) != 1 || batch.Rows[0].(model.Event).Object != object {
					t.Fatalf("forced exit changed the replayed batch: %+v", batch)
				}
			})
		}
	}
}

func pr33RunStderrShutdownChild(t *testing.T, scenario, ready, second, survived string) {
	t.Helper()
	if strings.HasSuffix(scenario, "/blocked") {
		pr33FillStderrPipe(t)
	}
	insertStarted := make(chan struct{})
	var once sync.Once
	// No network is reachable. Keep an actual Writer -> ClickHouse insert in
	// progress; its own 30s client timeout is longer than the assertion window.
	// Globals belong to this isolated child and are never changed while main runs.
	http.DefaultTransport = collectorRegressionTransport(func(r *http.Request) (*http.Response, error) {
		once.Do(func() { close(insertStarted) })
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	done := make(chan struct{})
	go func() { defer close(done); main() }()
	select {
	case <-insertStarted:
	case <-done:
		t.Fatal("main returned before the pending insert")
	case <-time.After(5 * time.Second):
		t.Fatal("fixture did not reach the pending insert")
	}
	fmt.Println(ready)
	if !strings.HasPrefix(scenario, "deadline/") {
		sig := syscall.SIGTERM
		if strings.HasPrefix(scenario, "sigint/") {
			sig = syscall.SIGINT
		}
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
		// Separate deliveries to avoid OS coalescing of equal pending signals.
		time.Sleep(100 * time.Millisecond)
		fmt.Println(second)
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	// Write directly to stdout before Cleanup can unblock stderr and allow the
	// delayed os.Exit(1). Otherwise that late exit could hide t.Fatal's output.
	fmt.Println(survived)
	t.Fatal("forced shutdown waited for stderr instead of terminating")
}

func pr33FillStderrPipe(t *testing.T) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Closing the reader first releases any blocked write during cleanup.
		reader.Close()
		writer.Close()
	})
	fd := int(writer.Fd())
	if err := syscall.SetNonblock(fd, true); err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 4096)
	for written := 0; ; {
		n, err := syscall.Write(fd, chunk)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.EAGAIN) {
			if len(chunk) == 1 {
				break
			}
			chunk = chunk[:1] // Fill any remaining space smaller than PIPE_BUF.
			continue
		}
		if err != nil || n <= 0 {
			t.Fatalf("fill stderr pipe: n=%d, err=%v", n, err)
		}
		written += n
		if written >= 2<<20 {
			t.Fatal("stderr fixture exceeded its 2 MiB pipe limit")
		}
	}
	if err := syscall.SetNonblock(fd, false); err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
}
