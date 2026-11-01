package main

import (
	"encoding/json"
	"fmt"
	"testing"
)

// coraza-caddy 2.6 processRequest copies the client Host to ServerName;
// Coraza 3.8 AuditLog then copies ServerName to transaction.server_id.
// Neither field identifies the machine that produced the audit record:
// https://github.com/corazawaf/coraza-caddy/blob/v2.6.0/http.go
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazawaf/transaction.go
func TestCorazaAuditHostCannotManufactureScannerNodes(t *testing.T) {
	hosts := []string{"one.attacker.test", "two.attacker.test", "three.attacker.test"}
	var audits []any
	for i, host := range hosts {
		audits = append(audits, map[string]any{
			"transaction": map[string]any{
				"client_ip": "203.0.113.50", "server_id": host,
				// The Caddy connector has no local socket address and writes "".
				"host_ip": "", "host_port": 0, "is_interrupted": true,
				"id":       fmt.Sprintf("host-fixture-%d", i),
				"producer": map[string]any{"rule_engine": "On"},
				"request": map[string]any{
					"method": "GET", "uri": "/.git/config",
					"headers": map[string][]string{"host": {host}},
				},
			},
			"messages": []any{map[string]any{
				"data":          nil,
				"error_message": `[client "203.0.113.50"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 5) [file "/crs/REQUEST-949-BLOCKING-EVALUATION.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "unknown"] [tag "anomaly-evaluation"]`,
			}},
		})
	}
	body, err := json.Marshal(audits)
	if err != nil {
		t.Fatal(err)
	}
	// The agent forwarding the three records is the same trusted sender.
	// waf-scanner-multihost counts distinct event.Node, with a threshold of 3.
	events := wafHTTPBatch(t, "/ingest/modsecurity", string(body), "192.0.2.10:31000")
	if len(events) != len(hosts) {
		t.Fatalf("accepted %d Coraza records, want %d", len(events), len(hosts))
	}
	nodes := make(map[string]bool)
	for i, e := range events {
		if e.Source != "waf.coraza" || e.Action != "http.attack" || e.Outcome != "deny" || e.SrcIP != "203.0.113.50" {
			t.Fatalf("fixture lost the real WAF decision: %+v", e)
		}
		if e.Attrs["host"] != hosts[i] {
			t.Errorf("request Host must remain available as evidence: %q", e.Attrs["host"])
		}
		if e.Node != "192.0.2.10" {
			t.Errorf("client Host %q became trusted Node %q; want sender 192.0.2.10", hosts[i], e.Node)
		}
		nodes[e.Node] = true
	}
	if len(nodes) != 1 {
		t.Errorf("one WAF manufactured %d distinct scanner nodes from client Host values: %v", len(nodes), nodes)
	}
}
