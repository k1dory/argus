package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/sink"
)

// Ошибка приёмника должна отменять работу, сохраняя обработку SIGTERM до
// окончания дренажа. Иначе первый SIGTERM от compose stop или E2E cleanup
// убивает процесс, хотя main ещё ждёт писателя. Дочерний процесс защищает
// остальной go test от этой регрессии; сетевые соединения здесь не нужны.
func TestPR23ListenerFailurePreservesSignalsUntilDrained(t *testing.T) {
	const scenario = "pr23_signal_during_listener_failure"
	const drained = "regression: listener failure drained after SIGTERM"
	if os.Getenv(collectorRegressionChildEnv) != scenario {
		out, err := runCollectorRegressionChild(t,
			"TestPR23ListenerFailurePreservesSignalsUntilDrained", scenario, 15*time.Second)
		if err != nil || !strings.Contains(out, drained) {
			t.Fatalf("SIGTERM прервал дренаж после ошибки приёмника: %v\n%s", err, out)
		}
		return
	}

	dir := t.TempDir()
	spoolDir := filepath.Join(dir, "spool")
	q, err := sink.NewDurableQueue(spoolDir, 1<<20, &sink.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{model.Event{Source: "pr23.regression", Object: "pending"}}); err != nil {
		t.Fatal(err)
	}
	q.Close()

	configPath := filepath.Join(dir, "collector.yml")
	// Недопустимый порт даёт ошибку запуска без DNS, внешнего сервера или
	// гонки за свободный порт. При этом spool уже содержит принятый батч.
	config := `listeners:
  syslog:
    udp: ""
    tcp: ""
  netflow:
    udp: ""
  http:
    addr: "127.0.0.1:65536"
    token: "pr23-test-token"
batch:
  pending_rows: 8
`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COLLECTOR_CONFIG", configPath)
	t.Setenv("SINK_SPOOL_DIR", spoolDir)
	t.Setenv("SINK_SPOOL_BYTES", "1048576")
	t.Setenv("CLICKHOUSE_URL", "http://clickhouse.invalid")
	t.Setenv("LOG_LEVEL", "error")

	// Удерживаем реальный путь Writer -> ClickHouse.insert, пока ошибка
	// запуска уже обработана. Транспорт соблюдает дедлайн HTTP-клиента.
	insertStarted := make(chan struct{})
	releaseInsert := make(chan struct{})
	var insertOnce, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseInsert) }) }
	defer release()
	originalTransport := http.DefaultTransport
	http.DefaultTransport = collectorRegressionTransport(func(r *http.Request) (*http.Response, error) {
		insertOnce.Do(func() { close(insertStarted) })
		select {
		case <-releaseInsert:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    r,
		}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = originalTransport })

	// run логирует ошибку после возврата runListener, то есть после его
	// stop(). Это барьер, а не предположение о скорости старта горутин.
	logReader, logWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	originalStderr := os.Stderr
	os.Stderr = logWriter
	logDone := make(chan struct{})
	listenerFailed := make(chan struct{})
	go func() {
		defer close(logDone)
		var once sync.Once
		scanner := bufio.NewScanner(logReader)
		for scanner.Scan() {
			line := scanner.Text()
			fmt.Fprintln(originalStderr, line)
			if strings.Contains(line, "msg=http ") && strings.Contains(line, "err=") {
				once.Do(func() { close(listenerFailed) })
			}
		}
	}()
	t.Cleanup(func() {
		os.Stderr = originalStderr
		logWriter.Close()
		<-logDone
		logReader.Close()
	})

	done := make(chan struct{})
	go func() { defer close(done); main() }()
	t.Cleanup(func() {
		// Даже при ошибке подготовки сначала завершаем main, затем
		// восстанавливаем глобальный транспорт, stderr и окружение.
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("main остался работать после очистки регрессионного теста")
		}
	})
	for _, step := range []struct {
		name string
		done <-chan struct{}
	}{
		{"вставка из spool", insertStarted},
		{"обработка ошибки приёмника", listenerFailed},
	} {
		select {
		case <-step.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("не завершился этап: %s", step.name)
		}
	}
	select {
	case <-done:
		t.Fatal("main вернулся до завершения вставки")
	default:
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Даём ОС доставить сигнал, сохраняя незавершённую вставку.
	time.Sleep(100 * time.Millisecond)
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("main не завершил дренаж")
	}
	recovered, err := sink.NewDurableQueue(spoolDir, 1<<20, &sink.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.Rows() != 0 {
		t.Fatalf("вставка не подтверждена: осталось %d строк", recovered.Rows())
	}
	fmt.Println(drained)
}
