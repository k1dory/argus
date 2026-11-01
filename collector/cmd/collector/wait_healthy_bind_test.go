package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Обещанный в PR быстрый отказ при занятом порте проверяется с настоящим
// main: искусственно закрыть exited недостаточно, если bind-ошибка до него
// вообще не доходит. Все приёмники и подставной ClickHouse изолированы в
// дочернем процессе; внешний сервер и внешние сигналы не нужны.
func TestWaitHealthyReportsHTTPBindFailure(t *testing.T) {
	if os.Getenv(collectorRegressionChildEnv) == "http_bind_failure" {
		occupied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer occupied.Close()
		dir := t.TempDir()
		path := filepath.Join(dir, "collector.yml")
		config := fmt.Sprintf(`listeners:
  syslog:
    udp: ""
    tcp: ""
  netflow:
    udp: ""
  http:
    addr: %q
    token: "tok-bind-regression"
batch:
  size: 2
  flush_ms: 50
  pending_rows: 8
`, occupied.Listener.Addr().String())
		if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("COLLECTOR_CONFIG", path)
		t.Setenv("CLICKHOUSE_URL", occupied.URL)
		t.Setenv("SINK_SPOOL_DIR", filepath.Join(dir, "spool"))
		t.Setenv("SINK_SPOOL_BYTES", "1048576")
		t.Setenv("LOG_LEVEL", "warn")

		exited := make(chan struct{})
		go func() { defer close(exited); main() }()
		// Короткий бюджет сохраняет тот же путь, что и 60 с в E2E.
		// При постоянной ошибке bind нужен сигнал завершения main,
		// а не сообщение об истечении срока ожидания /healthz.
		waitHealthy(t, occupied.URL+"/healthz", exited, time.Second)
		t.Fatal("коллектор признан готовым при занятом HTTP-порте")
	}

	out, err := runCollectorRegressionChild(t, "TestWaitHealthyReportsHTTPBindFailure", "http_bind_failure", 10*time.Second)
	requireCollectorRegressionFailure(t, out, err, "коллектор завершился до готовности")
}
