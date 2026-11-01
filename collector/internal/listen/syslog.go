// Package listen — сетевые приёмники коллектора. Каждый отдаёт строки или
// пакеты в обработчик; разбор и нормализация — снаружи.
package listen

import (
	"context"
	"log/slog"
	"net"
	"runtime"
)

// Peer — откуда пришла строка. Transport проставляет сам приёмник, а не
// отправитель: движок доверяет автоблокировку только tcp/tls/http/file/pull.
type Peer struct {
	Addr      string // IP отправителя (или метка файла)
	Transport string // udp | tcp | tls | http | file
	CN        string // CommonName клиентского сертификата при mTLS
	Node      string // узел по умолчанию для событий без узла (node: файлового источника)
	Format    string // объявленный формат источника (parse.Format*): files[].format, SYSLOG_PEER_FORMAT
}

// LineHandler получает одну строку syslog и сведения об отправителе.
type LineHandler func(line string, peer Peer)

func SyslogUDP(ctx context.Context, addr string, h LineHandler) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		_ = uc.SetReadBuffer(16 << 20) // всплески NGFW: 16 МБ буфера ядра
	}
	slog.Info("syslog udp listening", "addr", addr)
	go func() { <-ctx.Done(); pc.Close() }()
	// Чтение сокета — один цикл, разбор — пул воркеров: иначе парсер CEF
	// упирается в одно ядро и датаграммы теряются в буфере ядра.
	type raw struct {
		line, peer string
	}
	work := make(chan raw, 65536)
	for i := 0; i < workers(); i++ {
		go func() {
			for r := range work {
				Guard("syslog udp line", func() { h(r.line, Peer{Addr: r.peer, Transport: "udp"}) })
			}
		}()
	}
	defer close(work)
	buf := make([]byte, 64*1024)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("syslog udp read", "err", err)
			continue
		}
		work <- raw{line: string(buf[:n]), peer: hostOf(peer)}
	}
}

func workers() int {
	n := runtime.NumCPU()
	if n < 2 {
		return 2
	}
	if n > 8 {
		return 8
	}
	return n
}

// SyslogTCP — RFC 6587 (octet-counting или по строкам) с лимитами TCPOptions.
func SyslogTCP(ctx context.Context, addr string, opts TCPOptions, h LineHandler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	slog.Info("syslog tcp listening", "addr", addr, "max_conns", opts.withDefaults().MaxConns)
	return serveStream(ctx, ln, "tcp", opts, h)
}

// PacketHandler получает один датаграмм NetFlow/IPFIX.
type PacketHandler func(pkt []byte, exporter string)

func NetFlowUDP(ctx context.Context, addr string, h PacketHandler) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	slog.Info("netflow udp listening", "addr", addr)
	go func() { <-ctx.Done(); pc.Close() }()
	buf := make([]byte, 64*1024)
	for {
		n, peer, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("netflow udp read", "err", err)
			continue
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		Guard("netflow packet", func() { h(pkt, hostOf(peer)) })
	}
}

func hostOf(a net.Addr) string {
	if a == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return host
}
