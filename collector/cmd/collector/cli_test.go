package main

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/sink"
)

func TestEnvAndLogLevel(t *testing.T) {
	t.Setenv("ARGUS_T_ENV", "")
	if got := env("ARGUS_T_ENV", "def"); got != "def" {
		t.Errorf("пустая переменная → умолчание, получено %q", got)
	}
	t.Setenv("ARGUS_T_ENV", "v")
	if got := env("ARGUS_T_ENV", "def"); got != "v" {
		t.Errorf("заданная переменная: %q", got)
	}
	for raw, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug, "warn": slog.LevelWarn,
		"Error": slog.LevelError, "": slog.LevelInfo, "trace": slog.LevelInfo,
	} {
		t.Setenv("LOG_LEVEL", raw)
		if got := logLevel(); got != want {
			t.Errorf("LOG_LEVEL=%q → %v, want %v", raw, got, want)
		}
	}
}

func TestHasCEFLEEF(t *testing.T) {
	line := "<134>1 2026-01-01T00:00:00Z host app - - - CEF:0|Vendor|Product|1|100|name|5|src=1.2.3.4"
	if !hasCEF(line) || hasLEEF(line) {
		t.Error("CEF не распознан или принят за LEEF")
	}
	if !hasLEEF("LEEF:2.0|IBM|QRadar|1|x|") || hasCEF("plain syslog") {
		t.Error("LEEF/plain")
	}
}

func TestTLSConfigCheck(t *testing.T) {
	if err := (TLSConfig{}).check(false); err != nil {
		t.Errorf("выключенный TLS в проде допустим: %v", err)
	}
	if err := (TLSConfig{Addr: ":6514"}).check(false); err == nil || !strings.Contains(err.Error(), "SYSLOG_TLS_CERT") {
		t.Errorf("addr без cert/key в проде — отказ, получено %v", err)
	}
	if err := (TLSConfig{Addr: ":6514"}).check(true); err != nil {
		t.Errorf("стенд (ARGUS_DEV=1) допускает самоподписанный сертификат: %v", err)
	}
	if err := (TLSConfig{Addr: ":6514", Cert: "c.pem", Key: "k.pem"}).check(false); err != nil {
		t.Errorf("полный конфиг: %v", err)
	}
}

// Снимок heartbeat: счётчики за минуту обнуляются, но источник остаётся в
// списке — следующий снимок отдаёт его с нулём, и источник виден живым без событий.
func TestStatsSnapshotResetsPerMinute(t *testing.T) {
	st := &stats{perMin: map[string]uint32{}, listener: map[string]string{}, bySource: map[string]uint64{}}
	st.hit("sshd", "syslog")
	st.hit("sshd", "syslog")
	st.hit("netflow.core", "netflow")
	rows := st.snapshot()
	if len(rows) != 2 {
		t.Fatalf("строк %d, want 2: %+v", len(rows), rows)
	}
	byName := map[string]sink.HealthRow{}
	for _, r := range rows {
		byName[r.Source] = r
	}
	if byName["sshd"].Events1m != 2 || byName["sshd"].Listener != "syslog" || byName["netflow.core"].Events1m != 1 || byName["netflow.core"].Listener != "netflow" {
		t.Errorf("снимок: %+v", rows)
	}
	if byName["sshd"].SeenAt == "" || len(byName["sshd"].SeenAt) != 19 {
		t.Errorf("seen_at без миллисекунд (19 символов): %q", byName["sshd"].SeenAt)
	}
	again := st.snapshot()
	if len(again) != 2 || again[0].Events1m != 0 || again[1].Events1m != 0 {
		t.Errorf("второй снимок — те же источники с нулём: %+v", again)
	}
	if st.total.Load() != 3 || st.bySource["sshd"] != 2 {
		t.Errorf("накопительные счётчики не должны сбрасываться: total=%d sshd=%d", st.total.Load(), st.bySource["sshd"])
	}
	full := st.prometheus(0, 0, 0, &sink.Stats{}, true)
	if !strings.Contains(full, `argus_collector_source_last_seen_seconds{source="sshd"} 0`) {
		t.Errorf("last_seen источника: %q", full)
	}
}

func TestStatsHitConcurrent(t *testing.T) {
	st := &stats{perMin: map[string]uint32{}, listener: map[string]string{}, bySource: map[string]uint64{}}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); st.hit("a", "syslog") }()
	}
	wg.Wait()
	if st.total.Load() != 50 || st.perMin["a"] != 50 {
		t.Errorf("total=%d perMin=%d", st.total.Load(), st.perMin["a"])
	}
}

/* ===== replay-pcap ===== */

// pcapFile — классический pcap (LE, Ethernet) из переданных пакетов.
func pcapFile(linktype uint32, packets ...[]byte) []byte {
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], linktype)
	out := hdr
	for _, p := range packets {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], 1700000000)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(p)))
		out = append(out, rec...)
		out = append(out, p...)
	}
	return out
}

// ethIPv4 — Ethernet + IPv4 + транспорт (UDP 17 или TCP 6) с полезной нагрузкой;
// vlan — добавить тег 802.1Q.
func ethIPv4(proto byte, vlan bool, dport uint16, payload []byte) []byte {
	var l4 []byte
	switch proto {
	case 17:
		l4 = make([]byte, 8)
		binary.BigEndian.PutUint16(l4[0:2], 40000)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
	case 6:
		l4 = make([]byte, 20)
		binary.BigEndian.PutUint16(l4[0:2], 40000)
		binary.BigEndian.PutUint16(l4[2:4], dport)
		l4[12] = 5 << 4 // data offset 20 байт
	}
	l4 = append(l4, payload...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 7})
	copy(ip[16:20], []byte{192, 168, 0, 170})
	eth := make([]byte, 12)
	if vlan {
		eth = append(eth, 0x81, 0x00, 0x00, 0x64) // 802.1Q, VLAN 100
	}
	eth = append(eth, 0x08, 0x00)
	return append(append(eth, ip...), l4...)
}

func TestReplayPcapUsageAndErrors(t *testing.T) {
	if code := replayPcap(nil); code != 2 {
		t.Errorf("без аргументов → 2, получено %d", code)
	}
	if code := replayPcap([]string{filepath.Join(t.TempDir(), "missing.pcap")}); code != 1 {
		t.Errorf("нет файла → 1, получено %d", code)
	}
	bad := filepath.Join(t.TempDir(), "bad.pcapng")
	if err := os.WriteFile(bad, []byte("\x0a\x0d\x0d\x0a not a pcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := replayPcap([]string{bad}); code != 1 {
		t.Errorf("pcapng → 1, получено %d", code)
	}
}

func TestReplayPcapSendsPayloadLines(t *testing.T) {
	udp := ethIPv4(17, false, 514, []byte("<13>Jan  1 00:00:01 r1 sshd: line one\n<13>Jan  1 00:00:02 r1 sshd: line two\n"))
	tcpVLAN := ethIPv4(6, true, 5514, []byte("  <13>Jan  1 00:00:03 r2 sudo: line three  \n\n"))
	arp := append([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08, 0x06}, make([]byte, 28)...) // не IPv4 — пропускается
	path := filepath.Join(t.TempDir(), "sample.pcap")
	if err := os.WriteFile(path, pcapFile(1, udp, arp, tcpVLAN), 0o600); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var bodies []string
	var tokens, paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		tokens = append(tokens, r.Header.Get("X-Argus-Token"))
		paths = append(paths, r.Method+" "+r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	if code := replayPcap([]string{path, "--to", srv.URL + "/", "--token", "tok-1"}); code != 0 {
		t.Fatalf("код %d", code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || paths[0] != "POST /ingest/syslog" || tokens[0] != "tok-1" {
		t.Fatalf("запросы: %v токены %v тел %d", paths, tokens, len(bodies))
	}
	lines := strings.Split(bodies[0], "\n")
	want := []string{"<13>Jan  1 00:00:01 r1 sshd: line one", "<13>Jan  1 00:00:02 r1 sshd: line two", "<13>Jan  1 00:00:03 r2 sudo: line three"}
	if len(lines) != len(want) {
		t.Fatalf("строк %d: %q", len(lines), lines)
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("строка %d: %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestReplayPcapTokenFromEnvAndServerErrors(t *testing.T) {
	udp := ethIPv4(17, false, 514, []byte("<13>Jan  1 00:00:01 r1 sshd: x\n"))
	path := filepath.Join(t.TempDir(), "one.pcap")
	if err := os.WriteFile(path, pcapFile(1, udp), 0o600); err != nil {
		t.Fatal(err)
	}
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Argus-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("ARGUS_INGEST_TOKEN", "from-env")
	if code := replayPcap([]string{path, "--to", srv.URL}); code != 0 || got != "from-env" {
		t.Errorf("токен из окружения: код %d, токен %q", code, got)
	}

	deny := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer deny.Close()
	if code := replayPcap([]string{path, "--to", deny.URL}); code != 1 {
		t.Errorf("401 от приёмника → 1, получено %d", code)
	}
	if code := replayPcap([]string{path, "--to", "http://127.0.0.1:1"}); code != 1 {
		t.Errorf("приёмник недоступен → 1, получено %d", code)
	}
}
