package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/sink"
)

func TestExpandEnvDefaults(t *testing.T) {
	t.Setenv("ARGUS_T_SET", "value")
	t.Setenv("ARGUS_T_EMPTY", "")
	cases := map[string]string{
		"${ARGUS_T_SET}":             "value",
		"${ARGUS_T_SET:-def}":        "value",
		"${ARGUS_T_MISSING:-def}":    "def",
		"${ARGUS_T_MISSING:-}":       "",
		"${ARGUS_T_EMPTY:-fallback}": "fallback",
		"a ${ARGUS_T_SET} b ${ARGUS_T_MISSING:-http://x:1/v1} c": "a value b http://x:1/v1 c",
	}
	for in, want := range cases {
		if got := expandEnv(in); got != want {
			t.Errorf("%s → %q, want %q", in, got, want)
		}
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	t.Setenv("SYSLOG_TCP_MAX_CONNS", "77")
	t.Setenv("NETFLOW_EXPORTERS", "10.0.0.0/8")
	t.Setenv("SYSLOG_TLS_CLIENT_CA", "/certs/ca.pem")
	t.Setenv("SINK_PENDING_ROWS", "5000")
	t.Setenv("SINK_PENDING_BYTES", "1048576")
	t.Setenv("SYSLOG_TCP_MAX_CONNS_PER_IP", "8")
	c, err := loadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Listeners.Syslog.MaxConns != 77 || c.Listeners.NetFlow.Exporters != "10.0.0.0/8" ||
		c.Listeners.Syslog.TLS.ClientCA != "/certs/ca.pem" || c.Batch.PendingRows != 5000 ||
		c.Batch.PendingBytes != 1<<20 || c.Listeners.Syslog.MaxConnsPerIP != 8 {
		t.Errorf("env не применились: %+v %+v", c.Listeners, c.Batch)
	}
	t.Setenv("SINK_PENDING_ROWS", "")
	t.Setenv("SINK_PENDING_BYTES", "")
	if c, _ := loadConfig(""); c.Batch.PendingRows != 200_000 || c.Batch.PendingBytes != sink.DefaultPendingBytes {
		t.Errorf("умолчания: rows=%d bytes=%d", c.Batch.PendingRows, c.Batch.PendingBytes)
	}
}

// Реальный collector.yml с окружением compose: SYSLOG_TLS_ADDR задан, но пуст —
// TLS выключен, и прод-старт без сертификата не требуется.
func TestLoadConfigRealYamlEmptyEnv(t *testing.T) {
	for _, k := range []string{"SYSLOG_TLS_ADDR", "SYSLOG_TLS_CERT", "SYSLOG_TLS_KEY", "SYSLOG_TLS_CLIENT_CA",
		"ARGUS_INGEST_TOKEN", "WAF_AUDIT_LOG", "WAF_ERROR_LOG", "NETFLOW_EXPORTERS", "SINK_PENDING_ROWS",
		"SINK_PENDING_BYTES", "SYSLOG_TCP_MAX_CONNS", "SYSLOG_TCP_MAX_CONNS_PER_IP"} {
		t.Setenv(k, "")
	}
	c, err := loadConfig(filepath.Join("..", "..", "collector.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listeners.Syslog.TLS.Addr != "" {
		t.Fatalf("tls.addr должен быть пуст при SYSLOG_TLS_ADDR=\"\": %q", c.Listeners.Syslog.TLS.Addr)
	}
	if err := c.Listeners.Syslog.TLS.check(false); err != nil {
		t.Errorf("прод-старт без cert при выключенном TLS: %v", err)
	}
	if c.Listeners.Syslog.MaxConns != 1024 || c.Listeners.Syslog.MaxConnsPerIP != 64 ||
		c.Batch.PendingRows != 200_000 || c.Batch.PendingBytes != sink.DefaultPendingBytes {
		t.Errorf("умолчания из yml: %+v %+v", c.Listeners.Syslog, c.Batch)
	}
	// TLS включён, но cert не задан → отказ в проде, допустимо на стенде
	t.Setenv("SYSLOG_TLS_ADDR", ":6514")
	c, _ = loadConfig(filepath.Join("..", "..", "collector.yml"))
	if err := c.Listeners.Syslog.TLS.check(false); err == nil {
		t.Error("addr без cert в проде должен быть ошибкой")
	}
	if err := c.Listeners.Syslog.TLS.check(true); err != nil {
		t.Errorf("на стенде допустимо: %v", err)
	}
}

type memSink struct {
	mu   sync.Mutex
	rows int
}

func (m *memSink) InsertEvents(_ context.Context, rows []any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows += len(rows)
	return nil
}
func (m *memSink) InsertRejects(context.Context, []sink.Reject) error { return nil }

// Остановка: событие уже в queue, ctx отменён до того, как батчер его взял —
// оно должно дойти до ClickHouse, писатели выйти по Close.
func TestBatcherFlushesOnStop(t *testing.T) {
	ins := &memSink{}
	ws := &sink.Stats{}
	pq := sink.NewQueue(1000, ws)
	ctx, cancel := context.WithCancel(context.Background())
	var writers sync.WaitGroup
	for i := 0; i < 2; i++ {
		w := sink.NewWriter(ins, pq, ws)
		writers.Add(1)
		go func() { defer writers.Done(); w.Run(ctx) }()
	}
	queue := make(chan queuedEvent, 10)
	queue <- queuedEvent{event: model.Event{Source: "t", Object: "last"}}
	cancel()
	durableBatcher(ctx, queue, pq, 1, time.Hour, 2*time.Second)
	writers.Wait()
	if ws.Inserted.Load() != 1 || pq.Rows() != 0 || ins.rows != 1 {
		t.Fatalf("inserted=%d pending=%d rows=%d", ws.Inserted.Load(), pq.Rows(), ins.rows)
	}
}

func TestDurableBatcherPersistsFullBatchesOnStop(t *testing.T) {
	dir := t.TempDir()
	pq, err := sink.NewDurableQueue(dir, 1<<20, &sink.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	queue := make(chan queuedEvent, 3)
	acks := make(chan error, 3)
	for i := 0; i < 3; i++ {
		queue <- queuedEvent{event: model.Event{Source: "test", Object: "shutdown"}, ack: acks}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	durableBatcher(ctx, queue, pq, 1, time.Hour, time.Second)
	for i := 0; i < 3; i++ {
		if err := <-acks; err != nil {
			t.Fatal(err)
		}
	}
	recovered, err := sink.NewDurableQueue(dir, 1<<20, &sink.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Rows() != 3 {
		t.Fatalf("recovered %d rows, want 3", recovered.Rows())
	}
}

func TestDurableBatcherAcknowledgesAfterSpool(t *testing.T) {
	dir := t.TempDir()
	pq, err := sink.NewDurableQueue(dir, 1<<20, &sink.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	queue := make(chan queuedEvent, 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { durableBatcher(ctx, queue, pq, 10, 10*time.Millisecond, 100*time.Millisecond); close(done) }()
	ack := make(chan error, 1)
	queue <- queuedEvent{event: model.Event{Source: "test", Object: "accepted"}, ack: ack}
	select {
	case err := <-ack:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("батчер не подтвердил запись")
	}
	if pq.SpoolBytes() == 0 {
		t.Fatal("подтверждение до записи на диск")
	}
	cancel()
	<-done
	recovered, err := sink.NewDurableQueue(dir, 1<<20, &sink.Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Rows() != 1 {
		t.Fatalf("replay: rows=%d", recovered.Rows())
	}
}

func TestHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte(`{"status":"ok"}`)) }))
	defer ok.Close()
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	if code := healthcheck(ok.URL+"/healthz", time.Second); code != 0 {
		t.Errorf("200 → %d", code)
	}
	if code := healthcheck(bad.URL+"/healthz", time.Second); code != 1 {
		t.Errorf("500 → %d", code)
	}
	if code := healthcheck("http://127.0.0.1:1/healthz", 200*time.Millisecond); code != 1 {
		t.Errorf("недоступен → %d", code)
	}
	if u := healthURL(""); u != "http://127.0.0.1:8088/healthz" {
		t.Errorf("healthURL без конфига: %q", u)
	}
}

func TestPrometheusAggregateHidesSources(t *testing.T) {
	st := &stats{perMin: map[string]uint32{}, listener: map[string]string{}, bySource: map[string]uint64{}}
	st.hit("ngfw.checkpoint", "syslog")
	agg := st.prometheus(1, 2, 3, &sink.Stats{}, false)
	if strings.Contains(agg, "ngfw.checkpoint") || !strings.Contains(agg, "argus_collector_sources 1") || !strings.Contains(agg, "argus_collector_dead_letter_total 0") {
		t.Errorf("агрегаты: %q", agg)
	}
	if !strings.Contains(agg, "argus_collector_pending_bytes 3") {
		t.Errorf("нет pending_bytes: %q", agg)
	}
	if fullM := st.prometheus(1, 2, 3, &sink.Stats{}, true); !strings.Contains(fullM, `source="ngfw.checkpoint"`) {
		t.Errorf("полная версия без источников: %q", fullM)
	}
}

func TestMergeAttrsAndStructured(t *testing.T) {
	e := model.Event{Attrs: map[string]string{"container": "own"}}
	mergeAttrs(&e, map[string]string{"container": "cfg", "node_role": " waf ", "empty": "", " ": "x"})
	if e.Attrs["container"] != "own" || e.Attrs["node_role"] != "waf" || len(e.Attrs) != 2 {
		t.Fatalf("mergeAttrs: %+v", e.Attrs)
	}
	var nilAttrs model.Event
	mergeAttrs(&nilAttrs, map[string]string{"container": "caddy"})
	if nilAttrs.Attrs["container"] != "caddy" {
		t.Fatalf("nil attrs: %+v", nilAttrs.Attrs)
	}
	attrsFromStructured(&e, map[string]string{"argus.container": "sd", "argus.pod": "p1", "argus.": "x", "meta.ip": "1.1.1.1", "argus.empty": ""})
	if e.Attrs["container"] != "own" || e.Attrs["pod"] != "p1" || e.Attrs["ip"] != "" || len(e.Attrs) != 3 {
		t.Fatalf("attrsFromStructured: %+v", e.Attrs)
	}
	attrsFromStructured(&e, nil)
}

func TestFileSourceNodeAndAttrsFromEnv(t *testing.T) {
	t.Setenv("WAF_ERROR_LOG", "/logs/waf/caddy.log")
	t.Setenv("WAF_NODE", "waf-01")
	t.Setenv("WAF_CONTAINER", "caddy-waf")
	cfg, err := loadConfig("../../collector.yml")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range cfg.Listeners.Files {
		if f.Path != "/logs/waf/caddy.log" {
			continue
		}
		found = true
		if f.Node != "waf-01" || f.Attrs["container"] != "caddy-waf" {
			t.Fatalf("file source: %+v", f)
		}
	}
	if !found {
		t.Fatalf("источник WAF_ERROR_LOG не найден: %+v", cfg.Listeners.Files)
	}
}
