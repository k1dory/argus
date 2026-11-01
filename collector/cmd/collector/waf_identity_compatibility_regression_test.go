package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

// Native ModSecurity v3 always emits time_stamp, including without audit H.
// producer and messages are emitted only with H; messages use details rather
// than Coraza's error_message. Client strings must not affect product identity.
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/transaction.cc#L1588-L1725
func TestPR16Round3NativeModSecurityProductAndNodeRemainStable(t *testing.T) {
	for _, trailer := range []bool{false, true} {
		for _, requestHeaders := range []bool{false, true} {
			t.Run(fmt.Sprintf("audit_H=%v/audit_B=%v", trailer, requestHeaders), func(t *testing.T) {
				request := map[string]any{"method": "GET", "uri": "/Coraza:%20Warning."}
				if requestHeaders {
					request["headers"] = map[string]string{"Host": "operator-waf", "User-Agent": "Coraza: Warning."}
				}
				transaction := map[string]any{
					"time_stamp": "Thu Oct 29 17:39:38 2026", "unique_id": "native-modsecurity",
					"client_ip": "203.0.113.50", "client_port": 51000,
					"host_ip": "192.0.2.10", "host_port": 443, "server_id": "operator-waf",
					"request": request, "response": map[string]int{"http_code": 200},
				}
				if trailer {
					transaction["producer"] = map[string]string{
						"modsecurity": "ModSecurity v3.0.12 (Linux)", "connector": "ModSecurity-nginx v1.0.3", "secrules_engine": "Enabled",
					}
					transaction["messages"] = []any{map[string]any{
						"message": "Header Coraza: Warning.",
						"details": map[string]any{"ruleId": "1001", "severity": "4", "data": "Coraza: Warning.", "tags": []string{"attack-protocol"}},
					}}
				}
				body, err := json.Marshal(map[string]any{"transaction": transaction})
				if err != nil {
					t.Fatal(err)
				}
				events := wafHTTPBatch(t, "/ingest/modsecurity", string(body), "192.0.2.20:31000")
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one native ModSecurity audit", len(events))
				}
				if e := events[0]; e.Source != "waf.modsecurity" || e.Product != "modsecurity" || e.Node != "operator-waf" || e.SessionID != "native-modsecurity" {
					t.Errorf("Coraza fallback changed native ModSecurity identity: %+v", e)
				}
			})
		}
	}
}

// Follow the actual Caddy Host -> SplitHostPort -> server_id transformation,
// including IPv6 and the extra port inside brackets. Both with and without H,
// no spelling of the client Host is an additional server for scanner rules.
func TestPR16Round3CorazaHostVariantsUseTrustedSender(t *testing.T) {
	for _, host := range []string{
		"host.attacker.test",
		"HOST.Attacker.Test.:443",
		"[host.attacker.test:8443]:443",
		"[2001:db8::1]:443",
		"[::ffff:192.0.2.99]:443",
		"2001:db8::1",
	} {
		for _, trailer := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/audit_H=%v", host, trailer), func(t *testing.T) {
				serverID := pr16CaddyServerName(t, host)
				body := pr16CorazaIdentityAudit(t, host, serverID, trailer)
				events := wafHTTPBatch(t, "/ingest/modsecurity", body, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one Coraza audit", len(events))
				}
				if e := events[0]; e.Source != "waf.coraza" || e.Node != "192.0.2.10" || e.Attrs["host"] != host || e.Outcome != "deny" {
					t.Errorf("client Host variant changed Coraza identity: host=%q server_id=%q event=%+v", host, serverID, e)
				}
			})
		}
	}
}
