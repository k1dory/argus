package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/devitex-soft/argus/policyd/internal/policy"
	"github.com/devitex-soft/argus/policyd/internal/server"
	"github.com/devitex-soft/argus/policyd/internal/store"
	"github.com/devitex-soft/argus/policyd/internal/wazuh"
)

func TestEnvOrAndEnvBool(t *testing.T) {
	t.Setenv("ARGUS_T_X", "")
	if envOr("ARGUS_T_X", "d") != "d" {
		t.Error("пусто → умолчание")
	}
	t.Setenv("ARGUS_T_X", "v")
	if envOr("ARGUS_T_X", "d") != "v" {
		t.Error("задано → значение")
	}
	cases := map[string]bool{"": true, "1": true, "true": true, " Yes ": true, "ON": true, "0": false, "no": false, "off": false, "мусор": false}
	for raw, want := range cases {
		t.Setenv("ARGUS_T_B", raw)
		if got := envBool("ARGUS_T_B", true); got != want {
			t.Errorf("envBool(%q, true)=%v want %v", raw, got, want)
		}
	}
	t.Setenv("ARGUS_T_B", "")
	if envBool("ARGUS_T_B", false) {
		t.Error("пусто → умолчание false")
	}
}

// fakeWazuh — API менеджера: авторизация, список агентов (с менеджером 000),
// SCA по агентам; для агента 003 SCA отвечает 500.
type fakeWazuh struct {
	mu       sync.Mutex
	scaCalls []string
	authFail bool
}

func (f *fakeWazuh) server(t *testing.T) *httptest.Server {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if f.authFail {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"title":"Unauthorized"}`)
			return
		}
		io.WriteString(w, "jwt-token")
	})
	list := func(w http.ResponseWriter, items []map[string]any) {
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"affected_items": items, "total_affected_items": len(items)}, "error": 0})
	}
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		list(w, []map[string]any{
			{"id": "000", "name": "manager", "status": "active", "version": "Wazuh v4.12.0", "lastKeepAlive": now},
			{"id": "001", "name": "web-01", "ip": "10.0.0.1", "status": "active", "version": "Wazuh v4.12.0", "lastKeepAlive": now, "os": map[string]any{"platform": "ubuntu"}},
			{"id": "002", "name": "db-01", "status": "disconnected", "version": "Wazuh v4.2.0", "lastKeepAlive": "2020-01-01T00:00:00Z"},
			{"id": "003", "name": "app-01", "status": "active", "version": "Wazuh v4.12.0", "lastKeepAlive": now},
		})
	})
	mux.HandleFunc("GET /sca/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f.mu.Lock()
		f.scaCalls = append(f.scaCalls, id)
		f.mu.Unlock()
		if id == "003" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		list(w, []map[string]any{
			{"policy_id": "cis_ubuntu22-04", "name": "CIS Ubuntu 22.04", "score": 90, "pass": 90, "fail": 10, "invalid": 0},
			{"policy_id": "cis_docker", "name": "CIS Docker", "score": 40, "pass": 4, "fail": 6, "invalid": 2},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// fakeCH — ClickHouse, запоминающий строки INSERT; fail → 500.
type fakeCH struct {
	mu   sync.Mutex
	rows []store.VerdictRow
	fail bool
}

func (f *fakeCH) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if f.fail {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "Code: 241. DB::Exception: Memory limit")
			return
		}
		if !strings.Contains(r.URL.Query().Get("query"), "INSERT INTO argus.policy_verdicts") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		dec := json.NewDecoder(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		for {
			var row store.VerdictRow
			if err := dec.Decode(&row); err != nil {
				break
			}
			f.rows = append(f.rows, row)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newClient(t *testing.T, srv *httptest.Server) *wazuh.Client {
	t.Helper()
	wz, err := wazuh.New(srv.URL, "wazuh", "secret", wazuh.TLSOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return wz
}

func realEngine(t *testing.T) *policy.Engine {
	t.Helper()
	e, err := policy.New(context.Background(), "../../../policies", []string{"agent", "sca"})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestRunRoundVerdictsAndUnknowns(t *testing.T) {
	wzf := &fakeWazuh{}
	chf := &fakeCH{}
	snap := server.NewSnapshot(time.Minute)
	err := runRound(context.Background(), quietLog(), newClient(t, wzf.server(t)), realEngine(t),
		store.New(chf.server(t).URL, "argus", "default", ""), snap, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ok, why := snap.Health(); !ok || why != "ok" {
		t.Errorf("снимок после раунда: %v %q", ok, why)
	}
	// SCA запрашивается только у активных агентов, менеджер 000 не трогается.
	wzf.mu.Lock()
	sca := strings.Join(wzf.scaCalls, ",")
	wzf.mu.Unlock()
	if sca != "001,003" {
		t.Errorf("SCA запросы: %q, want 001,003", sca)
	}
	chf.mu.Lock()
	rows := chf.rows
	chf.mu.Unlock()
	byKey := map[string]store.VerdictRow{}
	for _, r := range rows {
		byKey[r.EntityType+"/"+r.EntityID] = r
	}
	if _, ok := byKey["agent/000"]; ok {
		t.Error("менеджер 000 не оценивается")
	}
	if r := byKey["agent/001"]; r.Status != store.StatusPass || r.Compliant != 1 || r.Policy != "wazuh/agent" || r.EntityName != "web-01" {
		t.Errorf("свежий агент: %+v", r)
	}
	if r := byKey["agent/002"]; r.Status != store.StatusFail || len(r.Violations) != 2 {
		t.Errorf("отключённый старый агент — 2 нарушения: %+v", r)
	}
	if r := byKey["sca/001/cis_ubuntu22-04"]; r.Status != store.StatusPass || r.EntityName != "web-01 · CIS Ubuntu 22.04" || r.Policy != "wazuh/sca" {
		t.Errorf("SCA pass: %+v", r)
	}
	if r := byKey["sca/001/cis_docker"]; r.Status != store.StatusFail || len(r.Violations) != 2 {
		t.Errorf("SCA с низкой оценкой и invalid — 2 нарушения: %+v", r)
	}
	if r := byKey["sca/003"]; r.Status != store.StatusUnknown || !strings.HasPrefix(r.Violations[0], "SCA fetch failed: ") || r.Compliant != 0 {
		t.Errorf("SCA 500 → unknown: %+v", r)
	}
	if len(rows) != 6 {
		t.Errorf("строк %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		if len(r.EvaluatedAt) != 19 {
			t.Errorf("evaluated_at: %q", r.EvaluatedAt)
		}
	}
}

func TestRunRoundPolicyEvalFailure(t *testing.T) {
	// Политика с result не-объектом: Eval возвращает ошибку по каждому агенту,
	// SCA при этом не запрашивается.
	dir := t.TempDir()
	for name, body := range map[string]string{
		"agent.rego": "package wazuh.agent\nimport rego.v1\nresult := 1\n",
		"sca.rego":   "package wazuh.sca\nimport rego.v1\nresult := {\"compliant\": true, \"violations\": []}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	eng, err := policy.New(context.Background(), dir, []string{"agent", "sca"})
	if err != nil {
		t.Fatal(err)
	}
	wzf := &fakeWazuh{}
	chf := &fakeCH{}
	snap := server.NewSnapshot(time.Minute)
	if err := runRound(context.Background(), quietLog(), newClient(t, wzf.server(t)), eng,
		store.New(chf.server(t).URL, "argus", "default", ""), snap, time.Minute, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if len(wzf.scaCalls) != 0 {
		t.Errorf("после ошибки политики агента SCA не запрашивается: %v", wzf.scaCalls)
	}
	if len(chf.rows) != 3 {
		t.Fatalf("строк %d: %+v", len(chf.rows), chf.rows)
	}
	for _, r := range chf.rows {
		if r.Status != store.StatusUnknown || !strings.HasPrefix(r.Violations[0], "policy eval failed: ") {
			t.Errorf("ожидался unknown с причиной: %+v", r)
		}
	}
}

func TestRunRoundFailures(t *testing.T) {
	// Wazuh не авторизует → ошибка раунда до оценки, ClickHouse не вызывается.
	wzf := &fakeWazuh{authFail: true}
	chf := &fakeCH{}
	err := runRound(context.Background(), quietLog(), newClient(t, wzf.server(t)), realEngine(t),
		store.New(chf.server(t).URL, "argus", "default", ""), server.NewSnapshot(time.Minute), time.Minute, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "fetch agents from Wazuh API") {
		t.Errorf("ошибка API: %v", err)
	}
	if len(chf.rows) != 0 {
		t.Error("без агентов вставки нет")
	}
	// Контекст отменён до раунда — та же ветка, сообщение с причиной.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	snapC := server.NewSnapshot(time.Minute)
	err = runRound(cancelled, quietLog(), newClient(t, (&fakeWazuh{}).server(t)), realEngine(t),
		store.New(chf.server(t).URL, "argus", "default", ""), snapC, time.Minute, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "fetch agents") || !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("отменённый контекст: %v", err)
	}
	if ok, _ := snapC.Health(); !ok {
		t.Error("ошибку раунда в снимок пишет main через SetError, runRound снимок не трогает")
	}

	// ClickHouse лёг: снимок уже обновлён (полезен для /verdicts), ошибка наверх.
	wzf = &fakeWazuh{}
	chf = &fakeCH{fail: true}
	snap := server.NewSnapshot(time.Minute)
	err = runRound(context.Background(), quietLog(), newClient(t, wzf.server(t)), realEngine(t),
		store.New(chf.server(t).URL, "argus", "default", ""), snap, time.Minute, 5*time.Second)
	if err == nil || !strings.Contains(err.Error(), "store verdicts") {
		t.Errorf("ошибка вставки: %v", err)
	}
	if ok, why := snap.Health(); !ok || why != "ok" {
		t.Errorf("снимок обновляется до вставки: %v %q", ok, why)
	}
}

// Процесс целиком: окружение → политики → первый раунд → HTTP /healthz и
// /verdicts → остановка по SIGTERM. os.Exit в main только при ошибках конфигурации.
func TestMainEndToEnd(t *testing.T) {
	wzf := &fakeWazuh{}
	chf := &fakeCH{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	t.Setenv("POLL_INTERVAL", "1m")
	t.Setenv("PER_AGENT_TIMEOUT", "2s") // устаревшее имя — предупреждение в лог
	t.Setenv("POLICY_DIR", "../../../policies")
	t.Setenv("WAZUH_API_URL", wzf.server(t).URL)
	t.Setenv("WAZUH_API_PASSWORD", "secret")
	t.Setenv("WAZUH_INSECURE_TLS", "true")
	t.Setenv("CLICKHOUSE_URL", chf.server(t).URL)
	t.Setenv("LISTEN_ADDR", addr)
	t.Setenv("POLICYD_TOKEN", "pd-token")

	done := make(chan struct{})
	go func() { defer close(done); main() }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		chf.mu.Lock()
		n := len(chf.rows)
		chf.mu.Unlock()
		if n == 6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("первый раунд не записан: строк %d", n)
		}
		time.Sleep(50 * time.Millisecond)
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/healthz: %d", resp.StatusCode)
	}
	resp, err = http.Get("http://" + addr + "/verdicts")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("/verdicts без токена: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodGet, "http://"+addr+"/verdicts", nil)
	req.Header.Set("Authorization", "Bearer pd-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "cis_ubuntu22-04") {
		t.Errorf("/verdicts: %d %s", resp.StatusCode, body)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("main не завершился по SIGTERM")
	}
}
