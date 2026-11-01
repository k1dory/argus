package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

const collectorRegressionChildEnv = "ARGUS_COLLECTOR_REGRESSION_CHILD"

type collectorRegressionTransport func(*http.Request) (*http.Response, error)

func (f collectorRegressionTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// Fatal должен завершить дочерний тест, а не внешний проверяющий тест.
// Каждый сценарий получает отдельный процесс: подмена DefaultTransport,
// signal.NotifyContext и возможные утечки main не затронут другие тесты.
func runCollectorRegressionChild(t *testing.T, testName, scenario string, timeout time.Duration) (string, error) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable,
		"-test.run=^"+regexp.QuoteMeta(testName)+"$",
		"-test.count=1", "-test.v", "-test.timeout="+timeout.String())
	// Никакие адреса ClickHouse, credentials или настройки источников из
	// окружения разработчика не должны попасть в процесс с настоящим main.
	dir := t.TempDir()
	cmd.Dir = dir
	cmd.Env = []string{collectorRegressionChildEnv + "=" + scenario, "TMPDIR=" + dir, "GOTRACEBACK=all"}
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("дочерний тест не завершился: %v\n%s", ctx.Err(), out)
	}
	if strings.Contains(string(out), "WARNING: DATA RACE") {
		t.Fatalf("гонка в дочернем тесте:\n%s", out)
	}
	return string(out), err
}

func requireCollectorRegressionFailure(t *testing.T, out string, err error, diagnostic string) {
	t.Helper()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !strings.Contains(out, diagnostic) {
		t.Fatalf("ожидалось падение дочернего теста с %q; err=%v\n%s", diagnostic, err, out)
	}
}

// Проверяем поведение реального waitHealthy. Ответы транспорта не требуют
// сокетов и не дублируют алгоритм ожидания. live — контроль, что корректная
// готовность после временного 503 по-прежнему принимается.
func TestWaitHealthyLifecycle(t *testing.T) {
	if scenario := os.Getenv(collectorRegressionChildEnv); scenario != "" {
		exited := make(chan struct{})
		timeout := 5 * time.Second
		switch scenario {
		case "live", "exits_during_probe":
		case "already_exited":
			close(exited)
		case "late_success":
			timeout = 25 * time.Millisecond
		default:
			t.Fatalf("неизвестный сценарий %q", scenario)
		}

		attempts := 0
		http.DefaultTransport = collectorRegressionTransport(func(r *http.Request) (*http.Response, error) {
			attempts++
			if scenario == "exits_during_probe" && attempts == 1 {
				// main завершился, пока запрос уже выполнялся.
				close(exited)
			}
			if scenario == "late_success" {
				// Укладывается в HTTP-таймаут 2 с, но превышает общий бюджет.
				// Транспорт соблюдает context, чтобы исправленный helper мог
				// отменить запрос по общему deadline.
				timer := time.NewTimer(250 * time.Millisecond)
				defer timer.Stop()
				select {
				case <-r.Context().Done():
					return nil, r.Context().Err()
				case <-timer.C:
				}
				if err := r.Context().Err(); err != nil {
					return nil, err
				}
			}
			status := http.StatusOK
			if scenario == "live" && attempts == 1 {
				status = http.StatusServiceUnavailable
			}
			return &http.Response{
				StatusCode: status,
				Status:     http.StatusText(status),
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`{"status":"ok"}`)),
				Request:    r,
			}, nil
		})
		waitHealthy(t, "http://127.0.0.1/healthz", exited, timeout)
		t.Log("waitHealthy вернул успех")
		return
	}

	for _, tc := range []struct {
		name       string
		diagnostic string
	}{
		{name: "live"},
		{name: "already_exited", diagnostic: "коллектор завершился до готовности"},
		{name: "exits_during_probe", diagnostic: "коллектор завершился до готовности"},
		{name: "late_success", diagnostic: "коллектор не поднялся за"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runCollectorRegressionChild(t, "TestWaitHealthyLifecycle", tc.name, 10*time.Second)
			if tc.diagnostic == "" {
				if err != nil || !strings.Contains(out, "waitHealthy вернул успех") {
					t.Fatalf("живой коллектор не признан готовым: %v\n%s", err, out)
				}
				return
			}
			requireCollectorRegressionFailure(t, out, err, tc.diagnostic)
		})
	}
}
