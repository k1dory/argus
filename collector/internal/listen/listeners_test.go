package listen

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// pickPort — свободный порт на loopback: приёмники принимают адрес строкой,
// «:0» им не передать и порт потом не узнать.
func pickPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprintf("127.0.0.1:%d", l.Addr().(*net.TCPAddr).Port)
}

// awaitCond ждёт условие не дольше 5 с.
func awaitCond(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("не дождался: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type lineSink struct {
	mu    sync.Mutex
	lines []string
	peers []Peer
}

func (s *lineSink) handle(line string, p Peer) {
	if strings.Contains(line, "boom") {
		panic("ядовитая строка")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, line)
	s.peers = append(s.peers, p)
}

func (s *lineSink) count() int { s.mu.Lock(); defer s.mu.Unlock(); return len(s.lines) }

func (s *lineSink) snapshot() ([]string, []Peer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...), append([]Peer(nil), s.peers...)
}

// UDP-приёмник: датаграмма → строка с transport=udp и адресом отправителя;
// паника в обработчике считается и не валит приёмник; отмена контекста
// завершает цикл без ошибки.
func TestSyslogUDPDeliversAndSurvivesPanic(t *testing.T) {
	addr := pickPort(t)
	sink := &lineSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- SyslogUDP(ctx, addr, sink.handle) }()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Пока сокет не привязан, датаграмма пропадает молча — шлём до первого приёма.
	awaitCond(t, "первая строка по UDP", func() bool {
		_, _ = c.Write([]byte("<34>1 - fw app - - - hello udp\n"))
		return sink.count() >= 1
	})
	lines, peers := sink.snapshot()
	if lines[0] != "<34>1 - fw app - - - hello udp\n" || peers[0].Transport != "udp" || peers[0].Addr != "127.0.0.1" || peers[0].CN != "" {
		t.Errorf("строка/peer: %q %+v", lines[0], peers[0])
	}
	before := Metrics.Panics.Load()
	awaitCond(t, "паника перехвачена", func() bool {
		_, _ = c.Write([]byte("boom"))
		return Metrics.Panics.Load() > before
	})
	// приёмник жив после паники
	n := sink.count()
	awaitCond(t, "строка после паники", func() bool {
		_, _ = c.Write([]byte("after"))
		return sink.count() > n
	})
	cancel()
	if err := <-done; err != nil {
		t.Errorf("после отмены контекста ожидался nil, got %v", err)
	}
	if err := SyslogUDP(context.Background(), "256.0.0.1:1", sink.handle); err == nil {
		t.Error("непривязываемый адрес должен дать ошибку")
	}
}

func TestNetFlowUDPDeliversPacketsAndSurvivesPanic(t *testing.T) {
	addr := pickPort(t)
	var mu sync.Mutex
	var pkts [][]byte
	var exporters []string
	h := func(pkt []byte, exporter string) {
		if pkt[0] == 0xff {
			panic("кривой пакет")
		}
		mu.Lock()
		defer mu.Unlock()
		pkts = append(pkts, pkt)
		exporters = append(exporters, exporter)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- NetFlowUDP(ctx, addr, h) }()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(pkts) }
	awaitCond(t, "первый пакет NetFlow", func() bool {
		_, _ = c.Write([]byte{0, 9, 0, 1, 1, 2, 3, 4})
		return count() >= 1
	})
	mu.Lock()
	if string(pkts[0]) != string([]byte{0, 9, 0, 1, 1, 2, 3, 4}) || exporters[0] != "127.0.0.1" {
		t.Errorf("пакет/экспортёр: %v %q", pkts[0], exporters[0])
	}
	mu.Unlock()
	before := Metrics.Panics.Load()
	awaitCond(t, "паника перехвачена", func() bool {
		_, _ = c.Write([]byte{0xff, 1})
		return Metrics.Panics.Load() > before
	})
	cancel()
	if err := <-done; err != nil {
		t.Errorf("после отмены контекста ожидался nil, got %v", err)
	}
	if err := NetFlowUDP(context.Background(), "256.0.0.1:1", h); err == nil {
		t.Error("непривязываемый адрес должен дать ошибку")
	}
}

func dialRetry(t *testing.T, addr string) net.Conn {
	t.Helper()
	var c net.Conn
	awaitCond(t, "приёмник слушает "+addr, func() bool {
		var err error
		c, err = net.DialTimeout("tcp", addr, time.Second)
		return err == nil
	})
	return c
}

// TCP-приёмник: в одном соединении строка по \n и кадр octet-counting (RFC 6587),
// transport=tcp; счётчик открытых соединений возвращается к исходному.
func TestSyslogTCPNewlineAndOctetCounting(t *testing.T) {
	addr := pickPort(t)
	sink := &lineSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- SyslogTCP(ctx, addr, TCPOptions{MaxConns: 4}, sink.handle) }()
	c := dialRetry(t, addr)
	msg := "<34>1 - fw app - - - two"
	if _, err := fmt.Fprintf(c, "<34>1 - fw app - - - one\r\n%d %s", len(msg), msg); err != nil {
		t.Fatal(err)
	}
	awaitCond(t, "две строки по TCP", func() bool { return sink.count() >= 2 })
	c.Close()
	lines, peers := sink.snapshot()
	if lines[0] != "<34>1 - fw app - - - one" || lines[1] != msg {
		t.Errorf("строки: %q", lines)
	}
	if peers[0].Transport != "tcp" || peers[0].Addr != "127.0.0.1" {
		t.Errorf("peer: %+v", peers[0])
	}
	awaitCond(t, "соединение закрыто и слот освобождён", func() bool { return Metrics.ActiveConns.Load() == 0 })
	cancel()
	if err := <-done; err != nil {
		t.Errorf("после отмены контекста ожидался nil, got %v", err)
	}
	if err := SyslogTCP(context.Background(), "256.0.0.1:1", TCPOptions{}, sink.handle); err == nil {
		t.Error("непривязываемый адрес должен дать ошибку")
	}
}

// TLS-приёмник на стенде (Dev: самоподписанный сертификат): клиент без
// сертификата принимается, transport=tls, CN пуст.
func TestSyslogTLSDevSelfSigned(t *testing.T) {
	addr := pickPort(t)
	sink := &lineSink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- SyslogTLS(ctx, addr, TLSOptions{Dev: true}, TCPOptions{}, sink.handle) }()
	var c *tls.Conn
	awaitCond(t, "TLS-приёмник слушает", func() bool {
		var err error
		c, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // стенд, самоподписанный
		return err == nil
	})
	if cn := c.ConnectionState().PeerCertificates[0].Subject.CommonName; cn != "argus-collector" {
		t.Errorf("CN самоподписанного сертификата: %q", cn)
	}
	if _, err := c.Write([]byte("<34>1 - fw app - - - over tls\n")); err != nil {
		t.Fatal(err)
	}
	awaitCond(t, "строка по TLS", func() bool { return sink.count() >= 1 })
	c.Close()
	lines, peers := sink.snapshot()
	if lines[0] != "<34>1 - fw app - - - over tls" || peers[0].Transport != "tls" || peers[0].CN != "" || peers[0].Addr != "127.0.0.1" {
		t.Errorf("строка/peer: %q %+v", lines[0], peers[0])
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("после отмены контекста ожидался nil, got %v", err)
	}
}

func TestSyslogTLSAndTLSConfigErrors(t *testing.T) {
	h := func(string, Peer) {}
	if err := SyslogTLS(context.Background(), pickPort(t), TLSOptions{}, TCPOptions{}, h); err == nil || !strings.Contains(err.Error(), "ARGUS_DEV") {
		t.Errorf("без cert/key вне стенда: %v", err)
	}
	if err := SyslogTLS(context.Background(), "256.0.0.1:1", TLSOptions{Dev: true}, TCPOptions{}, h); err == nil {
		t.Error("непривязываемый адрес должен дать ошибку")
	}
	dir := t.TempDir()
	if _, err := tlsConfig(TLSOptions{Cert: filepath.Join(dir, "no.crt"), Key: filepath.Join(dir, "no.key")}, ":0"); err == nil {
		t.Error("несуществующие cert/key должны дать ошибку")
	}
	_, _, crt, key := certPair(t, dir, "srv", "collector", false, nil, nil)
	if _, err := tlsConfig(TLSOptions{Cert: crt, Key: key, ClientCA: filepath.Join(dir, "no-ca.pem")}, ":0"); err == nil {
		t.Error("отсутствующий client_ca должен дать ошибку")
	}
	garbage := filepath.Join(dir, "garbage.pem")
	os.WriteFile(garbage, []byte("not a pem"), 0o600)
	if _, err := tlsConfig(TLSOptions{Cert: crt, Key: key, ClientCA: garbage}, ":0"); err == nil || !strings.Contains(err.Error(), "нет сертификатов") {
		t.Errorf("client_ca без сертификатов: %v", err)
	}
	cfg, err := tlsConfig(TLSOptions{Cert: crt, Key: key}, ":0")
	if err != nil || cfg.ClientAuth != tls.NoClientCert || cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("cert/key без client_ca: %v %+v", err, cfg)
	}
}

type noSysInfo struct{ os.FileInfo }

func (noSysInfo) Sys() any { return nil }

func TestHostOfRemoteHostInodeOf(t *testing.T) {
	if hostOf(nil) != "" {
		t.Error("nil-адрес → пустая строка")
	}
	if got := hostOf(&net.UnixAddr{Name: "/run/x.sock", Net: "unix"}); got != "/run/x.sock" {
		t.Errorf("адрес без порта возвращается как есть: %q", got)
	}
	if got := hostOf(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 514}); got != "::1" {
		t.Errorf("IPv6 без скобок: %q", got)
	}
	if got := hostOf(&net.TCPAddr{IP: net.ParseIP("10.0.0.7"), Port: 6514}); got != "10.0.0.7" {
		t.Errorf("IPv4: %q", got)
	}
	r := httptest.NewRequest("POST", "/ingest/syslog", nil)
	r.RemoteAddr = "10.1.2.3:4567"
	if remoteHost(r) != "10.1.2.3" {
		t.Errorf("remoteHost с портом: %q", remoteHost(r))
	}
	r.RemoteAddr = "10.1.2.3"
	if remoteHost(r) != "10.1.2.3" {
		t.Errorf("remoteHost без порта: %q", remoteHost(r))
	}
	r.RemoteAddr = "[fd00::1]:80"
	if remoteHost(r) != "fd00::1" {
		t.Errorf("remoteHost IPv6: %q", remoteHost(r))
	}
	path := filepath.Join(t.TempDir(), "f")
	os.WriteFile(path, []byte("x"), 0o600)
	st, _ := os.Stat(path)
	if inodeOf(st) == 0 {
		t.Error("у настоящего файла inode ненулевой")
	}
	if inodeOf(noSysInfo{st}) != 0 {
		t.Error("без Stat_t inode = 0")
	}
}
