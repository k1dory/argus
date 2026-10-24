package listen

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// certPair пишет сертификат (подписанный parent или сам собой) и ключ в dir.
func certPair(t *testing.T, dir, name, cn string, isCA bool, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:        isCA, BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	keyDer, _ := x509.MarshalECPrivateKey(key)
	cp, kp := filepath.Join(dir, name+".crt"), filepath.Join(dir, name+".key")
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0o600)
	return cert, key, cp, kp
}

func TestTLSRequiresCertOutsideDev(t *testing.T) {
	if _, err := tlsConfig(TLSOptions{}, ":0"); err == nil || !strings.Contains(err.Error(), "ARGUS_DEV") {
		t.Errorf("без cert/key и без Dev должна быть ошибка, got %v", err)
	}
	if cfg, err := tlsConfig(TLSOptions{Dev: true}, ":0"); err != nil || len(cfg.Certificates) != 1 {
		t.Errorf("Dev → самоподписанный: %v", err)
	}
}

func TestMTLSPeerCN(t *testing.T) {
	dir := t.TempDir()
	ca, caKey, caPath, _ := certPair(t, dir, "ca", "argus-test-ca", true, nil, nil)
	_, _, srvCrt, srvKey := certPair(t, dir, "server", "collector", false, ca, caKey)
	_, _, cliCrt, cliKey := certPair(t, dir, "client", "fw-01.example", false, ca, caKey)
	_, _, rogueCrt, rogueKey := certPair(t, dir, "rogue", "rogue", false, nil, nil)

	cfg, err := tlsConfig(TLSOptions{Cert: srvCrt, Key: srvKey, ClientCA: caPath}, ":0")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("client_ca задан — ожидается RequireAndVerifyClientCert")
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var got []Peer
	done := make(chan struct{})
	go func() {
		serveStream(ctx, tls.NewListener(raw, cfg), "tls", TCPOptions{}, func(line string, p Peer) {
			mu.Lock()
			got = append(got, p)
			mu.Unlock()
		})
		close(done)
	}()
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	dial := func(crt, key string) error {
		cert, err := tls.LoadX509KeyPair(crt, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := tls.Dial("tcp", raw.Addr().String(), &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, ServerName: "127.0.0.1"})
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err := c.Write([]byte("<34>1 - fw app - - - hello\n")); err != nil {
			return err
		}
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = c.Read(make([]byte, 1)) // сервер закроет по нашему Close/EOF; ошибка handshake придёт здесь
		return err
	}
	if err := dial(cliCrt, cliKey); err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("клиент с сертификатом от CA: %v", err)
	}
	if err := dial(rogueCrt, rogueKey); err == nil || strings.Contains(err.Error(), "timeout") {
		t.Errorf("чужой сертификат должен быть отвергнут, got %v", err)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Transport != "tls" || got[0].CN != "fw-01.example" || got[0].Addr != "127.0.0.1" {
		t.Errorf("peer: %+v", got)
	}
}
