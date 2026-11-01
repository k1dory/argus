//go:build unix

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A failed listener must not leave main waiting forever for a source doing
// uncancellable file I/O. The FIFO models a stalled state-file read in S3.Run;
// unlike a RoundTripper that ignores context, it exercises a real blocking path.
// The existing listener-signal test covers preservation of the first SIGTERM.
// Here a second explicit signal must allow the operator to force termination.
func TestPR23StalledShutdownCanBeForced(t *testing.T) {
	const prefix = "pr23_stalled_shutdown_"
	const ready = "regression: listener failed while state-file read is stalled"
	const second = "regression: sending second shutdown signal"
	const returned = "regression: main returned after source recovery"
	scenario := os.Getenv(collectorRegressionChildEnv)
	if !strings.HasPrefix(scenario, prefix) {
		for _, name := range []string{"source_recovers", "sigterm", "sigint", "deadline"} {
			t.Run(name, func(t *testing.T) {
				out, err := runCollectorRegressionChild(t,
					"TestPR23StalledShutdownCanBeForced", prefix+name, 20*time.Second)
				if !strings.Contains(out, ready) || strings.Contains(out, "--- FAIL:") {
					t.Fatalf("shutdown regression: %v\n%s", err, out)
				}
				if name == "source_recovers" {
					if err != nil || !strings.Contains(out, returned) {
						t.Fatalf("source recovery did not unblock main: %v\n%s", err, out)
					}
					return
				}
				if name == "deadline" {
					// Без сигналов: дренаж ограничен ARGUS_SHUTDOWN_TIMEOUT, затем exit 1.
					var exitErr *exec.ExitError
					// Строку лога не проверяем: stderr здесь перехвачен pipe-копировщиком,
					// и os.Exit опережает его. Ребёнок сам падает, если дедлайна нет.
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || strings.Contains(out, "shutdown deadline did not terminate") {
						t.Fatalf("hung drain did not exit by deadline: %v\n%s", err, out)
					}
					return
				}
				if !strings.Contains(out, second) {
					t.Fatalf("process exited before the second signal: %v\n%s", err, out)
				}
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) {
					t.Fatalf("expected forced nonzero exit: %v\n%s", err, out)
				}
				sig := syscall.SIGTERM
				if name == "sigint" {
					sig = syscall.SIGINT
				}
				status, ok := exitErr.Sys().(syscall.WaitStatus)
				if !ok || !(status.Signaled() && status.Signal() == sig ||
					status.Exited() && (status.ExitStatus() == 1 || status.ExitStatus() == 128+int(sig))) {
					t.Fatalf("unexpected termination status: %v\n%s", err, out)
				}
			})
		}
		return
	}

	dir := t.TempDir()
	stateFile := filepath.Join(dir, "s3.state")
	if err := syscall.Mkfifo(stateFile, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "collector.yml")
	config := fmt.Sprintf(`listeners:
  syslog:
    udp: ""
    tcp: ""
  netflow:
    udp: ""
  http:
    addr: "127.0.0.1:65536"
    token: "pr23-shutdown-token"
s3:
  - name: "pr23-stalled-source"
    endpoint: "http://s3.invalid"
    bucket: "fixture"
    access_key: "fixture"
    secret_key: "fixture"
    state_file: %q
batch:
  pending_rows: 8
`, stateFile)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COLLECTOR_CONFIG", configPath)
	t.Setenv("SINK_SPOOL_DIR", filepath.Join(dir, "spool"))
	t.Setenv("SINK_SPOOL_BYTES", "1048576")
	t.Setenv("CLICKHOUSE_URL", "http://clickhouse.invalid")
	t.Setenv("LOG_LEVEL", "error")
	if scenario == prefix+"deadline" {
		t.Setenv("ARGUS_SHUTDOWN_TIMEOUT", "300ms")
	}
	// No network request is expected: S3 reads its state before checking ctx,
	// and the invalid HTTP port fails without binding or resolving a hostname.
	// Fail closed if a future change unexpectedly reaches an HTTP client.
	originalTransport := http.DefaultTransport
	http.DefaultTransport = collectorRegressionTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network disabled in stalled-shutdown regression")
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = writer
	listenerFailed := make(chan struct{})
	logsDone := make(chan struct{})
	go func() {
		defer close(logsDone)
		scanner := bufio.NewScanner(reader)
		reported := false
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(originalStderr, line)
			if !reported && strings.Contains(line, "msg=http ") && strings.Contains(line, "err=") {
				reported = true
				close(listenerFailed) // runListener has already called cancel().
			}
		}
	}()
	t.Cleanup(func() {
		os.Stderr = originalStderr
		writer.Close()
		<-logsDone
		reader.Close()
	})

	done := make(chan struct{})
	go func() { defer close(done); main() }()
	stateWriter := -1
	release := func() {
		if stateWriter >= 0 {
			_ = syscall.Close(stateWriter)
			stateWriter = -1
		}
	}
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("main did not return after releasing the state-file fixture")
		}
	})

	// O_WRONLY|O_NONBLOCK succeeds only once the real S3 source opens the
	// read end. Keep the write end open without bytes, so ReadFile cannot finish.
	for deadline := time.Now().Add(5 * time.Second); ; {
		stateWriter, err = syscall.Open(stateFile, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.ENXIO) || time.Now().After(deadline) {
			t.Fatalf("S3 did not open the state-file fixture: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case <-listenerFailed:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP listener failure was not observed")
	}
	select {
	case <-done:
		t.Fatal("main returned before the stalled source was released")
	default:
	}
	fmt.Println(ready)
	if scenario == prefix+"source_recovers" {
		release()
		select {
		case <-done:
			fmt.Println(returned)
		case <-time.After(5 * time.Second):
			t.Fatal("source recovery did not complete shutdown")
		}
		return
	}

	if scenario == prefix+"deadline" {
		select {
		case <-done:
			t.Fatal("main returned instead of exiting by the shutdown deadline")
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown deadline did not terminate the stalled drain")
		}
	}
	sig := syscall.SIGTERM
	if scenario == prefix+"sigint" {
		sig = syscall.SIGINT
	}
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
	// Separate deliveries so the OS cannot coalesce the two pending signals.
	time.Sleep(100 * time.Millisecond)
	fmt.Println(second)
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		t.Fatal("main returned without reporting a forced nonzero process exit")
	case <-time.After(2 * time.Second):
		t.Fatal("second signal ignored: main is still blocked in wg.Wait; exit 1 and automatic restart are unreachable until file I/O completes")
	}
}
