package wazuh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newAPI поднимает TLS-заглушку Wazuh API: аутентификация и один агент.
func newAPI(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /security/user/authenticate", func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "wazuh" || p != "secret" {
			http.Error(w, "bad credentials", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte("jwt-token"))
	})
	mux.HandleFunc("GET /agents", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer jwt-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"affected_items":       []map[string]any{{"id": "001", "name": "web-01", "status": "active"}},
				"total_affected_items": 1,
			},
			"error": 0,
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func fingerprint(srv *httptest.Server) string {
	sum := sha256.Sum256(srv.Certificate().Raw)
	return hex.EncodeToString(sum[:])
}

func caFile(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func agents(t *testing.T, srv *httptest.Server, opts TLSOptions) error {
	t.Helper()
	c, err := New(srv.URL, "wazuh", "secret", opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	list, err := c.Agents(context.Background())
	if err != nil {
		return err
	}
	if len(list) != 1 || list[0].ID != "001" {
		t.Fatalf("unexpected agents: %+v", list)
	}
	return nil
}

func TestTLSDefaultRejectsSelfSigned(t *testing.T) {
	srv := newAPI(t)
	err := agents(t, srv, TLSOptions{})
	if err == nil {
		t.Fatal("self-signed certificate must be rejected without CA/pin/insecure")
	}
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Fatalf("expected certificate verification error, got %v", err)
	}
}

func TestTLSCAFileAccepts(t *testing.T) {
	srv := newAPI(t)
	if err := agents(t, srv, TLSOptions{CAFile: caFile(t, srv)}); err != nil {
		t.Fatalf("CA file must make the connection trusted: %v", err)
	}
}

func TestTLSCAFileMissing(t *testing.T) {
	if _, err := New("https://x", "u", "p", TLSOptions{CAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Fatal("missing CA file must fail at construction")
	}
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a pem"), 0o600)
	if _, err := New("https://x", "u", "p", TLSOptions{CAFile: bad}); err == nil {
		t.Fatal("CA file without certificates must fail at construction")
	}
}

func TestTLSPinAccepts(t *testing.T) {
	srv := newAPI(t)
	fp := fingerprint(srv)
	// Разные написания одного отпечатка: hex, верхний регистр, с двоеточиями.
	upper := strings.ToUpper(fp)
	var colon []string
	for i := 0; i < len(fp); i += 2 {
		colon = append(colon, fp[i:i+2])
	}
	for _, v := range []string{fp, upper, strings.Join(colon, ":")} {
		if err := agents(t, srv, TLSOptions{CertSHA256: v}); err != nil {
			t.Fatalf("pin %q must be accepted: %v", v, err)
		}
	}
}

func TestTLSPinMismatchRejects(t *testing.T) {
	srv := newAPI(t)
	wrong := strings.Repeat("ab", sha256.Size)
	err := agents(t, srv, TLSOptions{CertSHA256: wrong})
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("wrong pin must be rejected with fingerprint mismatch, got %v", err)
	}
	// Пиннинг важнее insecure: даже с Insecure=true неверный отпечаток — отказ.
	err = agents(t, srv, TLSOptions{CertSHA256: wrong, Insecure: true})
	if err == nil {
		t.Fatal("wrong pin must be rejected even with Insecure=true")
	}
}

func TestTLSPinMalformed(t *testing.T) {
	for _, v := range []string{"zz", "abcd", "not-hex-at-all"} {
		if _, err := New("https://x", "u", "p", TLSOptions{CertSHA256: v}); err == nil {
			t.Fatalf("malformed pin %q must fail at construction", v)
		}
	}
}

func TestTLSInsecureAccepts(t *testing.T) {
	srv := newAPI(t)
	if err := agents(t, srv, TLSOptions{Insecure: true}); err != nil {
		t.Fatalf("insecure mode must accept self-signed: %v", err)
	}
}

func TestTLSWarningsReflectPrecedence(t *testing.T) {
	cases := []struct {
		name string
		opts TLSOptions
		want []string // подстроки, по одной на предупреждение
	}{
		{"none", TLSOptions{}, nil},
		{"ca only", TLSOptions{CAFile: "ca.pem"}, nil},
		{"pin only", TLSOptions{CertSHA256: "ab"}, nil},
		{"insecure applied", TLSOptions{Insecure: true}, []string{"WAZUH_INSECURE_TLS=true"}},
		{"ca + pin → CA ignored", TLSOptions{CAFile: "ca.pem", CertSHA256: "ab"}, []string{"WAZUH_CA_FILE ignored"}},
		{"ca + insecure → insecure ignored, no scary warning", TLSOptions{CAFile: "ca.pem", Insecure: true}, []string{"WAZUH_INSECURE_TLS ignored"}},
		{"all three", TLSOptions{CAFile: "ca.pem", CertSHA256: "ab", Insecure: true}, []string{"WAZUH_CA_FILE ignored", "WAZUH_INSECURE_TLS ignored"}},
	}
	for _, c := range cases {
		got := c.opts.Warnings()
		if len(got) != len(c.want) {
			t.Errorf("%s: got %d warnings %q, want %d", c.name, len(got), got, len(c.want))
			continue
		}
		for i := range got {
			if !strings.Contains(got[i], c.want[i]) {
				t.Errorf("%s: warning %d = %q, want substring %q", c.name, i, got[i], c.want[i])
			}
			if strings.Contains(got[i], "not verified") && c.opts.CAFile != "" || strings.Contains(got[i], "not verified") && c.opts.CertSHA256 != "" {
				t.Errorf("%s: 'not verified' must only be reported when Insecure is actually applied: %q", c.name, got[i])
			}
		}
	}
}
