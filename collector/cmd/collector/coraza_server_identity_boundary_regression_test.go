package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
)

// coraza-caddy strips a port exactly once before calling SetServerName:
// https://github.com/corazawaf/coraza-caddy/blob/v2.6.0/http.go#L93
// net/http validates Host bytes, not whether a bracketed host is an IPv6
// address. Such a Host can therefore reach a Caddy route without a host matcher.
func TestPR16CorazaHostPortCannotManufactureNodes(t *testing.T) {
	for _, bracketed := range []bool{false, true} {
		t.Run(fmt.Sprintf("bracketed=%v", bracketed), func(t *testing.T) {
			nodes := map[string]bool{}
			for i := 1; i <= 3; i++ {
				host := fmt.Sprintf("host-%d.attacker.test:443", i)
				if bracketed {
					host = fmt.Sprintf("[host-%d.attacker.test:8443]:443", i)
				}
				serverID := pr16CaddyServerName(t, host)
				body := pr16CorazaIdentityAudit(t, host, serverID, true)
				events := wafHTTPBatch(t, "/ingest/modsecurity", body, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("accepted %d events, want 1", len(events))
				}
				e := events[0]
				if e.Source != "waf.coraza" || e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["host"] != host {
					t.Fatalf("fixture lost the real WAF decision or Host: %+v", e)
				}
				if e.Node != "192.0.2.10" {
					t.Errorf("Host=%q, connector server_id=%q became node=%q; want trusted sender", host, serverID, e.Node)
				}
				nodes[e.Node] = true
			}
			if len(nodes) != 1 {
				t.Errorf("one WAF manufactured %d nodes for waf-scanner-multihost: %v", len(nodes), nodes)
			}
		})
	}
}

// In Coraza 3.8.1 AuditLog, only part H creates transaction.producer.
// SecAuditLogParts ABKZ still includes the client-derived server_id and the
// structured rule data, so missing H must not promote that ID to a trusted node.
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazawaf/transaction.go
func TestPR16CorazaWithoutAuditTrailerCannotManufactureNodes(t *testing.T) {
	nodes := map[string]bool{}
	for i := 1; i <= 3; i++ {
		host := fmt.Sprintf("host-%d.attacker.test", i)
		body := pr16CorazaIdentityAudit(t, host, pr16CaddyServerName(t, host), false)
		events := wafHTTPBatch(t, "/ingest/modsecurity", body, "192.0.2.10:31000")
		if len(events) != 1 {
			t.Fatalf("accepted %d events, want 1", len(events))
		}
		e := events[0]
		if e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["rule_ids"] != "1001" || e.Attrs["host"] != host {
			t.Fatalf("ABKZ fixture lost the real decision or request evidence: %+v", e)
		}
		if e.Source != "waf.coraza" {
			t.Errorf("Coraza without part H was classified as %q", e.Source)
		}
		if e.Node != "192.0.2.10" {
			t.Errorf("Host %q became node %q when producer was absent; want trusted sender", host, e.Node)
		}
		nodes[e.Node] = true
	}
	if len(nodes) != 1 {
		t.Errorf("one WAF manufactured %d nodes without audit part H: %v", len(nodes), nodes)
	}
}

// Control: ModSecurity's server_id is operator-provided, including when it
// happens to equal Host or when Host is empty in the audit.
func TestPR16ModSecurityServerIDRemainsTrusted(t *testing.T) {
	for _, host := range []string{"operator-waf", ""} {
		t.Run(fmt.Sprintf("host=%q", host), func(t *testing.T) {
			body := wafAuditJSON(t, "operator-waf", "192.0.2.10", host)
			events := wafHTTPBatch(t, "/ingest/modsecurity", body, "192.0.2.20:31000")
			if len(events) != 1 {
				t.Fatalf("accepted %d events, want 1", len(events))
			}
			if e := events[0]; e.Source != "waf.modsecurity" || e.Node != "operator-waf" || e.Outcome != "deny" || e.Attrs["rule_ids"] != "949110" {
				t.Fatalf("Coraza identity filtering changed ModSecurity: %+v", e)
			}
		})
	}
}

func pr16CaddyServerName(t *testing.T, host string) string {
	t.Helper()
	// Request.Write applies net/http's Host-byte validation. Round-trip the
	// request without opening a socket, so an invalid fixture cannot pass by
	// simply assigning an arbitrary server_id to an audit object.
	req, err := http.NewRequest(http.MethodGet, "http://waf.example/config.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	var wire bytes.Buffer
	if err := req.Write(&wire); err != nil {
		t.Fatal(err)
	}
	parsed, err := http.ReadRequest(bufio.NewReader(&wire))
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Body.Close()
	if parsed.Host != host {
		t.Fatalf("net/http changed Host: got %q, want %q", parsed.Host, host)
	}
	serverName, _, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		return parsed.Host
	}
	return serverName
}

func pr16CorazaIdentityAudit(t *testing.T, host, serverID string, trailer bool) string {
	t.Helper()
	transaction := map[string]any{
		"timestamp": "2026/10/29 17:39:38", "unix_timestamp": int64(1793284778618840706),
		"id": "identity-boundary", "client_ip": "203.0.113.50", "client_port": 31000,
		"host_ip": "", "host_port": 0, "server_id": serverID, "is_interrupted": true,
		"request": map[string]any{
			"method": "GET", "uri": "/config.json", "protocol": "HTTP/1.1",
			"headers": map[string][]string{"host": {host}},
		},
	}
	if trailer {
		transaction["producer"] = map[string]string{"rule_engine": "On"}
	}
	body, err := json.Marshal(map[string]any{
		"transaction": transaction,
		"messages": []any{map[string]any{
			"message": "Header policy", "error_message": "",
			"data": map[string]any{
				"file": "/etc/coraza/local.conf", "line": 1, "id": 1001,
				"msg": "Header policy", "severity": "warning", "tags": []string{"attack-protocol"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
