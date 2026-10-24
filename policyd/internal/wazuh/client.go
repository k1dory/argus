// Package wazuh is a minimal client for the Wazuh manager REST API (port 55000).
// Authentication follows the documented flow: POST /security/user/authenticate
// with basic auth returns a JWT used as a Bearer token.
package wazuh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TLSOptions задаёт, как проверять сертификат Wazuh API.
// Приоритет: CertSHA256 (пиннинг) > CAFile (свой CA) > Insecure > системные CA.
type TLSOptions struct {
	// Insecure отключает проверку сертификата целиком. Только для стенда.
	Insecure bool
	// CAFile — PEM с корневым/промежуточным CA, которым подписан сертификат API.
	CAFile string
	// CertSHA256 — hex-отпечаток SHA-256 leaf-сертификата API (двоеточия и
	// регистр не важны). Совпадение отпечатка заменяет проверку цепочки.
	CertSHA256 string
}

// Warnings — что оператору стоит знать о выбранном режиме: какие опции
// проигнорированы из-за приоритета и применён ли Insecure на самом деле.
func (o TLSOptions) Warnings() []string {
	var out []string
	switch {
	case o.CertSHA256 != "":
		if o.CAFile != "" {
			out = append(out, "WAZUH_CA_FILE ignored: WAZUH_CERT_SHA256 pin takes precedence")
		}
		if o.Insecure {
			out = append(out, "WAZUH_INSECURE_TLS ignored: WAZUH_CERT_SHA256 pin takes precedence")
		}
	case o.CAFile != "":
		if o.Insecure {
			out = append(out, "WAZUH_INSECURE_TLS ignored: WAZUH_CA_FILE takes precedence")
		}
	case o.Insecure:
		out = append(out, "WAZUH_INSECURE_TLS=true: Wazuh API certificate is not verified; prefer WAZUH_CA_FILE or WAZUH_CERT_SHA256")
	}
	return out
}

// TLSConfig собирает tls.Config по опциям.
func (o TLSOptions) TLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if o.CertSHA256 != "" {
		want, err := parseFingerprint(o.CertSHA256)
		if err != nil {
			return nil, err
		}
		// Пиннинг: у самоподписанного сертификата Wazuh нет цепочки, которую
		// можно проверить, поэтому стандартная проверка отключается, а
		// подлинность гарантируется сравнением отпечатка leaf-сертификата.
		cfg.InsecureSkipVerify = true //nolint:gosec // проверка заменена пиннингом в VerifyConnection
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("wazuh tls: server presented no certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if got != want {
				return fmt.Errorf("wazuh tls: certificate fingerprint mismatch: got %s, want %s",
					hex.EncodeToString(got[:]), hex.EncodeToString(want[:]))
			}
			return nil
		}
		return cfg, nil
	}

	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("wazuh tls: read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("wazuh tls: no PEM certificates in %s", o.CAFile)
		}
		cfg.RootCAs = pool
		return cfg, nil
	}

	if o.Insecure {
		cfg.InsecureSkipVerify = true //nolint:gosec // явно включено оператором через WAZUH_INSECURE_TLS
	}
	return cfg, nil
}

func parseFingerprint(s string) ([32]byte, error) {
	var out [32]byte
	clean := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s))
	clean = strings.TrimPrefix(strings.ToLower(clean), "sha256")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return out, fmt.Errorf("wazuh tls: bad WAZUH_CERT_SHA256: %w", err)
	}
	if len(b) != sha256.Size {
		return out, fmt.Errorf("wazuh tls: bad WAZUH_CERT_SHA256: want %d hex bytes, got %d", sha256.Size, len(b))
	}
	copy(out[:], b)
	return out, nil
}

type Client struct {
	base string
	user string
	pass string
	http *http.Client

	mu    sync.Mutex
	token string
}

func New(base, user, pass string, tlsOpts TLSOptions) (*Client, error) {
	tlsCfg, err := tlsOpts.TLSConfig()
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &Client{
		base: strings.TrimRight(base, "/"),
		user: user,
		pass: pass,
		http: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

func (c *Client) authenticate(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base+"/security/user/authenticate?raw=true", nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authenticate: %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	c.mu.Lock()
	c.token = strings.TrimSpace(string(body))
	c.mu.Unlock()
	return nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	c.mu.Lock()
	token := c.token
	c.mu.Unlock()
	if token == "" {
		if err := c.authenticate(ctx); err != nil {
			return err
		}
	}

	for attempt := 0; attempt < 2; attempt++ {
		c.mu.Lock()
		token = c.token
		c.mu.Unlock()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			// JWT expired (900 s lifetime by default): re-authenticate once.
			if err := c.authenticate(ctx); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s: %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
		}
		return json.Unmarshal(body, out)
	}
	return fmt.Errorf("GET %s: unauthorized after token refresh", path)
}

type listResponse[T any] struct {
	Data struct {
		AffectedItems      []T `json:"affected_items"`
		TotalAffectedItems int `json:"total_affected_items"`
	} `json:"data"`
	Error int `json:"error"`
}

func getPaged[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	const limit = 500
	var items []T
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	for offset := 0; ; offset += limit {
		var page listResponse[T]
		url := fmt.Sprintf("%s%slimit=%d&offset=%d", path, sep, limit, offset)
		if err := c.get(ctx, url, &page); err != nil {
			return nil, err
		}
		if page.Error != 0 {
			return nil, fmt.Errorf("GET %s: API error code %d", path, page.Error)
		}
		items = append(items, page.Data.AffectedItems...)
		if len(items) >= page.Data.TotalAffectedItems || len(page.Data.AffectedItems) == 0 {
			return items, nil
		}
	}
}

type Agent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"`
	Version       string `json:"version"`
	LastKeepAlive string `json:"lastKeepAlive"`
	OS            struct {
		Platform string `json:"platform"`
	} `json:"os"`
}

func (c *Client) Agents(ctx context.Context) ([]Agent, error) {
	return getPaged[Agent](ctx, c,
		"/agents?select=id,name,ip,status,version,lastKeepAlive,os.platform")
}

// SCAPolicy is one Security Configuration Assessment policy summary for an agent.
type SCAPolicy struct {
	PolicyID string `json:"policy_id"`
	Name     string `json:"name"`
	Pass     int    `json:"pass"`
	Fail     int    `json:"fail"`
	Invalid  int    `json:"invalid"`
	Score    int    `json:"score"`
}

func (c *Client) SCA(ctx context.Context, agentID string) ([]SCAPolicy, error) {
	return getPaged[SCAPolicy](ctx, c, "/sca/"+agentID)
}

// StaleSeconds returns how long ago the agent last reported, or -1 if unknown.
func (a Agent) StaleSeconds(now time.Time) int64 {
	if a.LastKeepAlive == "" {
		return -1
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05-0700", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, a.LastKeepAlive); err == nil {
			// Будущие метки (в т.ч. сентинел 9999 года) дают отрицательное
			// значение — политика трактует его как "неизвестно" и жалуется.
			return int64(now.Sub(t).Seconds())
		}
	}
	return -1
}
