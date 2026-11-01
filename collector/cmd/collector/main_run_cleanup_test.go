package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Проблема существовала и до PR #19: Fatal до последнего SIGTERM оставляет
// main работающим. Вызываем сам E2E-тест, а не копию его запуска и очистки.
func TestMainEndToEndStopsOnFailure(t *testing.T) {
	const injectedFailure = "regression: injected /metrics failure"
	const cleanedUp = "regression: all collector listeners released"
	if os.Getenv(collectorRegressionChildEnv) == "metrics_failure" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.Proxy = nil
		defer transport.CloseIdleConnections()
		var cfg Config
		var configErr error
		var injected bool
		http.DefaultTransport = collectorRegressionTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/metrics" {
				// Сохраняем адреса до Fatal и отката t.Setenv/TempDir.
				cfg, configErr = loadConfig(os.Getenv("COLLECTOR_CONFIG"))
				injected = true
				return nil, errors.New(injectedFailure)
			}
			return transport.RoundTrip(r)
		})

		if t.Run("injected_metrics_failure", TestMainEndToEnd) {
			t.Fatal("E2E-тест неожиданно принял ошибку /metrics")
		}
		if !injected || configErr != nil {
			t.Fatalf("не удалось дойти до инъекции ошибки: injected=%v, config=%v", injected, configErr)
		}

		// t.Run возвращается после cleanup дочернего теста. Все четыре
		// порта должны быть доступны следующему тесту в том же процессе.
		leaked := false
		for _, listener := range []struct {
			network string
			addr    string
		}{
			{"tcp", cfg.Listeners.HTTP.Addr},
			{"tcp", cfg.Listeners.Syslog.TCP},
			{"udp", cfg.Listeners.Syslog.UDP},
			{"udp", cfg.Listeners.NetFlow.UDP},
		} {
			var err error
			if listener.network == "udp" {
				var conn net.PacketConn
				conn, err = net.ListenPacket(listener.network, listener.addr)
				if err == nil {
					conn.Close()
				}
			} else {
				var conn net.Listener
				conn, err = net.Listen(listener.network, listener.addr)
				if err == nil {
					conn.Close()
				}
			}
			if err != nil {
				leaked = true
				t.Errorf("после Fatal коллектор удерживает %s %s: %v", listener.network, listener.addr, err)
			}
		}
		if !leaked {
			// Код выхода всё равно 1 из-за ожидаемого Fatal во вложенном
			// E2E-тесте; отдельный маркер подтверждает, что cleanup выполнен.
			fmt.Println(cleanedUp)
		}
		return
	}

	out, err := runCollectorRegressionChild(t, "TestMainEndToEndStopsOnFailure", "metrics_failure", 90*time.Second)
	requireCollectorRegressionFailure(t, out, err, injectedFailure)
	if !strings.Contains(out, cleanedUp) {
		t.Fatalf("E2E-тест не освободил приёмники после падения:\n%s", out)
	}
}
