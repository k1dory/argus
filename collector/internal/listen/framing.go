package listen

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// TCPOptions — лимиты потоковых приёмников (TCP и TLS).
type TCPOptions struct {
	MaxConns          int           // одновременных соединений; лишние закрываются сразу (1024)
	MaxConnsPerIP     int           // одновременных соединений с одного IP (64, SYSLOG_TCP_MAX_CONNS_PER_IP)
	MaxFrame          int           // байт на кадр/строку; больше — соединение закрывается (1 МБ)
	FrameTimeout      time.Duration // на приём одного кадра целиком; не продлевается по байтам (5 мин)
	FirstFrameTimeout time.Duration // на первый кадр после accept/handshake (30 с): пустое соединение не держит слот 5 минут
}

func (o TCPOptions) withDefaults() TCPOptions {
	if o.MaxConns <= 0 {
		o.MaxConns = 1024
	}
	if o.MaxConnsPerIP <= 0 {
		o.MaxConnsPerIP = 64
	}
	if o.MaxFrame <= 0 {
		o.MaxFrame = 1 << 20
	}
	if o.FrameTimeout <= 0 {
		o.FrameTimeout = 5 * time.Minute
	}
	if o.FirstFrameTimeout <= 0 || o.FirstFrameTimeout > o.FrameTimeout {
		o.FirstFrameTimeout = min(30*time.Second, o.FrameTimeout)
	}
	return o
}

// readFrames читает поток syslog по RFC 6587: octet-counting («123 <pri>…»)
// или non-transparent framing (строки по \n). Определяется по первому байту.
// Дедлайн ставится на кадр: медленный клиент, капающий по байту, не держит
// соединение вечно. Кадр длиннее MaxFrame — соединение закрывается.
func readFrames(c net.Conn, peer Peer, opts TCPOptions, h LineHandler) {
	opts = opts.withDefaults()
	r := bufio.NewReaderSize(c, 64*1024)
	var line []byte
	timeout := opts.FirstFrameTimeout
	emit := func(s string) {
		timeout = opts.FrameTimeout
		Guard("syslog "+peer.Transport+" line", func() { h(s, peer) })
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(timeout))
		b, err := r.Peek(1)
		if err != nil {
			return
		}
		if b[0] >= '0' && b[0] <= '9' {
			lenStr, err := r.ReadSlice(' ')
			if errors.Is(err, bufio.ErrBufferFull) || len(lenStr) > 11 { // длина кадра — не больше 10 цифр
				oversize(peer, len(lenStr))
				return
			}
			if err != nil { // EOF/таймаут посреди длины — не oversize
				return
			}
			n, err := strconv.Atoi(string(lenStr[:len(lenStr)-1]))
			if err != nil || n <= 0 {
				return
			}
			if n > opts.MaxFrame {
				oversize(peer, n)
				return
			}
			buf := make([]byte, n)
			if _, err := io.ReadFull(r, buf); err != nil {
				return
			}
			emit(string(buf))
			continue
		}
		line = line[:0]
		for {
			chunk, err := r.ReadSlice('\n')
			line = append(line, chunk...)
			if len(line) > opts.MaxFrame {
				oversize(peer, len(line))
				return
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				continue
			}
			if len(line) > 0 {
				emit(trimNL(string(line)))
			}
			if err != nil {
				return
			}
			break
		}
	}
}

func oversize(peer Peer, n int) {
	Metrics.Oversize.Add(1)
	slog.Warn("syslog: кадр больше лимита, соединение закрыто", "peer", peer.Addr, "transport", peer.Transport, "bytes", n)
}

func trimNL(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

// perIP — счётчик открытых соединений по адресу: один сломанный клиент,
// открывающий соединения и молчащий, не должен занять весь семафор.
type perIP struct {
	mu    sync.Mutex
	conns map[string]int
}

func (p *perIP) acquire(ip string, limit int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns[ip] >= limit {
		return false
	}
	p.conns[ip]++
	return true
}

func (p *perIP) release(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns[ip] <= 1 {
		delete(p.conns, ip)
	} else {
		p.conns[ip]--
	}
}

// serveStream — общий цикл accept для TCP и TLS: семафор на число
// соединений, лимит на IP, горутина на соединение под recover.
func serveStream(ctx context.Context, ln net.Listener, transport string, opts TCPOptions, h LineHandler) error {
	opts = opts.withDefaults()
	go func() { <-ctx.Done(); ln.Close() }()
	sem := make(chan struct{}, opts.MaxConns)
	ips := &perIP{conns: map[string]int{}}
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			slog.Warn("syslog "+transport+" accept", "err", err)
			time.Sleep(50 * time.Millisecond) // не крутить цикл при EMFILE
			continue
		}
		ip := hostOf(conn.RemoteAddr())
		if !ips.acquire(ip, opts.MaxConnsPerIP) {
			conn.Close()
			if n := Metrics.ConnRejected.Add(1); n == 1 || n%1000 == 0 {
				slog.Warn("syslog "+transport+": лимит соединений с одного IP, отвергнуто", "max_per_ip", opts.MaxConnsPerIP, "rejected_total", n, "peer", ip)
			}
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			ips.release(ip)
			if n := Metrics.ConnRejected.Add(1); n == 1 || n%1000 == 0 {
				slog.Warn("syslog "+transport+": лимит соединений, отвергнуто", "max", opts.MaxConns, "rejected_total", n, "peer", ip)
			}
			continue
		}
		Metrics.ActiveConns.Add(1)
		SafeGo("syslog "+transport+" conn", func() {
			defer func() {
				conn.Close()
				Metrics.ActiveConns.Add(-1)
				ips.release(ip)
				<-sem
			}()
			peer := Peer{Addr: ip, Transport: transport}
			if tc, ok := conn.(*tls.Conn); ok {
				hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
				err := tc.HandshakeContext(hctx)
				cancel()
				if err != nil {
					slog.Debug("syslog tls handshake", "peer", peer.Addr, "err", err)
					return
				}
				if certs := tc.ConnectionState().PeerCertificates; len(certs) > 0 {
					peer.CN = peerName(certs[0])
				}
			}
			readFrames(conn, peer, opts, h)
		})
	}
}

// peerName — имя клиента из сертификата для attrs.peer_cn: CN, иначе первое
// SAN (DNS → URI → e-mail); современные CA выпускают сертификаты без CN.
func peerName(cert *x509.Certificate) string {
	name := cert.Subject.CommonName
	switch {
	case name != "":
	case len(cert.DNSNames) > 0:
		name = cert.DNSNames[0]
	case len(cert.URIs) > 0:
		name = cert.URIs[0].String()
	case len(cert.EmailAddresses) > 0:
		name = cert.EmailAddresses[0]
	}
	name, _ = model.Clean(name)
	return name
}

// TLSOptions — сертификаты приёмника RFC 5425.
type TLSOptions struct {
	Cert, Key string
	ClientCA  string // PEM с CA клиентов → mTLS (RequireAndVerifyClientCert)
	Dev       bool   // ARGUS_DEV=1: без cert/key — самоподписанный на старте
}

// SyslogTLS — RFC 5425: syslog поверх TLS. В бою cert/key обязательны;
// самоподписанный сертификат генерируется только на стенде (Dev).
func SyslogTLS(ctx context.Context, addr string, tlsOpts TLSOptions, opts TCPOptions, h LineHandler) error {
	cfg, err := tlsConfig(tlsOpts, addr)
	if err != nil {
		return err
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return err
	}
	slog.Info("syslog tls listening", "addr", addr, "mtls", cfg.ClientAuth == tls.RequireAndVerifyClientCert)
	return serveStream(ctx, ln, "tls", opts, h)
}

func tlsConfig(o TLSOptions, addr string) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	switch {
	case o.Cert != "" && o.Key != "":
		cert, err = tls.LoadX509KeyPair(o.Cert, o.Key)
	case o.Dev:
		cert, err = selfSigned()
		slog.Warn("syslog tls: самоподписанный сертификат — только для стенда", "addr", addr)
	default:
		return nil, errors.New("syslog tls: нужны cert и key (SYSLOG_TLS_CERT/SYSLOG_TLS_KEY); самоподписанный допустим только при ARGUS_DEV=1")
	}
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if o.ClientCA != "" {
		pemBytes, err := os.ReadFile(o.ClientCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, errors.New("syslog tls: в client_ca нет сертификатов")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "argus-collector"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"argus-collector", "localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDer, _ := x509.MarshalECPrivateKey(key)
	return tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}))
}
