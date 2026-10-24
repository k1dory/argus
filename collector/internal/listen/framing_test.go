package listen

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Строка 2 МБ без \n: соединение закрывается на лимите 1 МБ, обработчик не
// вызывается, в память уходит не больше лимита плюс буфер чтения.
func TestOversizeLineClosesConn(t *testing.T) {
	client, server := net.Pipe()
	before := Metrics.Oversize.Load()
	var calls atomic.Int64
	done := make(chan struct{})
	go func() {
		readFrames(server, Peer{Addr: "t", Transport: "tcp"}, TCPOptions{MaxFrame: 1 << 20, FrameTimeout: 10 * time.Second},
			func(string, Peer) { calls.Add(1) })
		server.Close()
		close(done)
	}()
	chunk := []byte(strings.Repeat("A", 32*1024))
	written := 0
	for written < 2<<20 {
		n, err := client.Write(chunk)
		written += n
		if err != nil {
			break
		}
	}
	<-done
	if written >= 2<<20 {
		t.Fatalf("приёмник вычитал все 2 МБ (%d) — лимит не сработал", written)
	}
	if written > 1<<20+2*64*1024 {
		t.Errorf("до закрытия принято %d байт — больше лимита и буфера", written)
	}
	if calls.Load() != 0 {
		t.Errorf("обработчик вызван %d раз для неполной строки", calls.Load())
	}
	if Metrics.Oversize.Load() != before+1 {
		t.Errorf("метрика oversize: %d → %d", before, Metrics.Oversize.Load())
	}
}

func TestOctetCountingOversizeAndNormal(t *testing.T) {
	client, server := net.Pipe()
	var got []string
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		readFrames(server, Peer{Transport: "tcp"}, TCPOptions{MaxFrame: 1 << 20}, func(l string, p Peer) {
			mu.Lock()
			got = append(got, l+"|"+p.Transport)
			mu.Unlock()
		})
		server.Close()
		close(done)
	}()
	msg := "<34>1 2026-09-14T12:00:00Z h app - - - hello"
	go func() {
		fmt.Fprintf(client, "%d %s", len(msg), msg)
		fmt.Fprintf(client, "%d %s", len(msg), msg)
		fmt.Fprintf(client, "%d ", 5<<20) // объявленный кадр больше лимита → закрытие
		buf := make([]byte, 1)
		client.Read(buf)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("приёмник не закрыл соединение по oversize octet-counting")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || got[0] != msg+"|tcp" {
		t.Errorf("кадры: %q", got)
	}
}

func TestFrameDeadlineNotExtendedByBytes(t *testing.T) {
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		readFrames(server, Peer{}, TCPOptions{FrameTimeout: 300 * time.Millisecond}, func(string, Peer) {})
		server.Close()
		close(done)
	}()
	// капаем по байту чаще дедлайна: кадр не завершается — соединение должно закрыться
	start := time.Now()
	for {
		client.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
		if _, err := client.Write([]byte("x")); err != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
		if time.Since(start) > 3*time.Second {
			t.Fatal("соединение живёт дольше дедлайна кадра")
		}
	}
	<-done
	if el := time.Since(start); el < 250*time.Millisecond || el > 2*time.Second {
		t.Errorf("закрыто через %v, ожидалось ~300 мс", el)
	}
}

// 1024 соединений открыты — 1025-е сервер закрывает сразу.
func TestMaxConnsRejects1025th(t *testing.T) {
	const maxConns = 1024
	// Клиент и сервер в одном процессе: два fd на соединение, плюс запас.
	needFDs(t, 2*(maxConns+1)+256)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan struct{})
	go func() {
		_ = serveStream(ctx, ln, "tcp", TCPOptions{MaxConns: maxConns, MaxConnsPerIP: 2 * maxConns}, func(string, Peer) {})
		close(serveDone)
	}()
	activeBefore, rejBefore := Metrics.ActiveConns.Load(), Metrics.ConnRejected.Load()
	conns := make([]net.Conn, 0, maxConns)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < maxConns; i++ {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatalf("не удалось открыть %d-е соединение: %v", i+1, err)
		}
		conns = append(conns, c)
	}
	deadline := time.Now().Add(10 * time.Second)
	for Metrics.ActiveConns.Load()-activeBefore < maxConns {
		if time.Now().After(deadline) {
			t.Fatalf("сервер принял %d из %d", Metrics.ActiveConns.Load()-activeBefore, maxConns)
		}
		time.Sleep(5 * time.Millisecond)
	}
	extra, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("1025-е соединение должно быть закрыто сервером, got err=%v", err)
	}
	if !waitRejected(rejBefore + 1) {
		t.Errorf("rejected: %d → %d", rejBefore, Metrics.ConnRejected.Load())
	}
	// принятое соединение при этом живо
	conns[0].SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conns[0].Read(make([]byte, 1)); err == io.EOF {
		t.Error("принятое соединение закрыто")
	}
	cancel()
	<-serveDone
}

func TestGuardRecovers(t *testing.T) {
	before := Metrics.Panics.Load()
	Guard("test", func() { panic("boom") })
	var idx []int
	Guard("test", func() { _ = idx[3] })
	if Metrics.Panics.Load() != before+2 {
		t.Errorf("panics: %d → %d", before, Metrics.Panics.Load())
	}
	// паника в обработчике строки не закрывает соединение
	client, server := net.Pipe()
	done := make(chan struct{})
	var n atomic.Int64
	go func() {
		readFrames(server, Peer{}, TCPOptions{}, func(l string, _ Peer) {
			n.Add(1)
			if l == "bad" {
				panic("parser")
			}
		})
		close(done)
	}()
	client.Write([]byte("bad\nok\n"))
	client.Close()
	<-done
	if n.Load() != 2 {
		t.Errorf("после паники обработано %d строк, want 2", n.Load())
	}
}

// 64 соединения с одного IP открыты — 65-е закрывается, хотя общий лимит далёк.
func TestMaxConnsPerIPRejects65th(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	const perIP = 64
	serveDone := make(chan struct{})
	go func() {
		_ = serveStream(ctx, ln, "tcp", TCPOptions{MaxConns: 1024}, func(string, Peer) {}) // MaxConnsPerIP по умолчанию 64
		close(serveDone)
	}()
	// соединения предыдущего теста закрываются асинхронно — дождаться нуля
	for w := time.Now(); Metrics.ActiveConns.Load() != 0 && time.Since(w) < 5*time.Second; {
		time.Sleep(5 * time.Millisecond)
	}
	activeBefore, rejBefore := Metrics.ActiveConns.Load(), Metrics.ConnRejected.Load()
	conns := make([]net.Conn, 0, perIP)
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for i := 0; i < perIP; i++ {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	deadline := time.Now().Add(10 * time.Second)
	for Metrics.ActiveConns.Load()-activeBefore < perIP {
		if time.Now().After(deadline) {
			t.Fatalf("сервер принял %d из %d", Metrics.ActiveConns.Load()-activeBefore, perIP)
		}
		time.Sleep(5 * time.Millisecond)
	}
	extra, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("65-е соединение с одного IP должно быть закрыто, got err=%v", err)
	}
	if !waitRejected(rejBefore + 1) {
		t.Errorf("rejected: %d → %d", rejBefore, Metrics.ConnRejected.Load())
	}
	// одно закрыли — слот освободился, новое принимается
	conns[0].Close()
	for Metrics.ActiveConns.Load()-activeBefore >= perIP {
		if time.Now().After(deadline) {
			t.Fatal("слот не освободился")
		}
		time.Sleep(5 * time.Millisecond)
	}
	again, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	again.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := again.Read(make([]byte, 1)); err == io.EOF {
		t.Error("после освобождения слота соединение отвергнуто")
	}
	cancel()
	<-serveDone
}

// Соединение без единого байта закрывается по FirstFrameTimeout, а после
// первого кадра действует длинный FrameTimeout.
func TestFirstFrameTimeout(t *testing.T) {
	opts := TCPOptions{FirstFrameTimeout: 200 * time.Millisecond, FrameTimeout: 10 * time.Second}
	client, server := net.Pipe()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		readFrames(server, Peer{}, opts, func(string, Peer) {})
		server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("молчащее соединение живёт дольше FirstFrameTimeout")
	}
	if el := time.Since(start); el < 150*time.Millisecond || el > 2*time.Second {
		t.Errorf("закрыто через %v, ожидалось ~200 мс", el)
	}
	client.Close()

	client, server = net.Pipe()
	done = make(chan struct{})
	var n atomic.Int64
	go func() {
		readFrames(server, Peer{}, opts, func(string, Peer) { n.Add(1) })
		server.Close()
		close(done)
	}()
	client.Write([]byte("<34>1 - h a - - - hello\n"))
	select {
	case <-done:
		t.Fatal("после первого кадра соединение закрыто по короткому таймауту")
	case <-time.After(500 * time.Millisecond):
	}
	client.Close()
	<-done
	if n.Load() != 1 {
		t.Errorf("кадров %d, want 1", n.Load())
	}
}

// Обрыв посреди длины octet-counting — не oversize; длина из 12 цифр — oversize.
func TestOctetCountingEOFNotOversize(t *testing.T) {
	before := Metrics.Oversize.Load()
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		readFrames(server, Peer{}, TCPOptions{}, func(string, Peer) {})
		close(done)
	}()
	client.Write([]byte("12"))
	client.Close()
	<-done
	if Metrics.Oversize.Load() != before {
		t.Errorf("EOF посреди длины посчитан как oversize")
	}
	client, server = net.Pipe()
	done = make(chan struct{})
	go func() {
		readFrames(server, Peer{}, TCPOptions{}, func(string, Peer) {})
		server.Close()
		close(done)
	}()
	go func() { client.Write([]byte("123456789012 x")); client.Read(make([]byte, 1)) }()
	<-done
	if Metrics.Oversize.Load() != before+1 {
		t.Errorf("длина из 12 цифр должна быть oversize")
	}
}

func TestPeerNameFallback(t *testing.T) {
	u, _ := url.Parse("spiffe://corp/fw-03")
	cases := []struct {
		cert *x509.Certificate
		want string
	}{
		{&x509.Certificate{Subject: pkix.Name{CommonName: "fw-01"}, DNSNames: []string{"fw-01.example"}}, "fw-01"},
		{&x509.Certificate{DNSNames: []string{"fw-02.example", "alt"}}, "fw-02.example"},
		{&x509.Certificate{URIs: []*url.URL{u}}, "spiffe://corp/fw-03"},
		{&x509.Certificate{EmailAddresses: []string{"fw-04@example.com"}}, "fw-04@example.com"},
		{&x509.Certificate{Subject: pkix.Name{CommonName: "evil\x1b[31m\nname"}}, "evil name"},
		{&x509.Certificate{}, ""},
	}
	for i, c := range cases {
		if got := peerName(c.cert); got != c.want {
			t.Errorf("%d: peerName = %q, want %q", i, got, c.want)
		}
	}
}

func TestGuardRepanicsAbortHandler(t *testing.T) {
	before := Metrics.Panics.Load()
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("ErrAbortHandler должен пробрасываться: %v", r)
		}
		if Metrics.Panics.Load() != before {
			t.Error("ErrAbortHandler посчитан как паника")
		}
	}()
	Guard("http", func() { panic(http.ErrAbortHandler) })
	t.Error("паника не проброшена")
}

// waitRejected ждёт счётчик отказов: сервер закрывает соединение раньше,
// чем увеличивает счётчик, и клиент видит EOF до инкремента.
func waitRejected(want uint64) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		if Metrics.ConnRejected.Load() == want {
			return true
		}
	}
	return Metrics.ConnRejected.Load() == want
}
