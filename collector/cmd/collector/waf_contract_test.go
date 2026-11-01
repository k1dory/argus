package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

// Exercise the registered HTTP route with the production parser callbacks;
// capture the batch at the durable-queue boundary without network or ClickHouse.
func wafHTTPBatch(t *testing.T, path, body, remote string) []model.Event {
	t.Helper()
	n := &normalize.Normalizer{}
	var events []model.Event
	h := &listen.HTTPHandlers{
		Token: "waf-contract-token",
		ParseLine: func(line string, peer listen.Peer) (model.Event, bool) {
			return parseSyslogLine(n, nil, line, peer)
		},
		ParseWAFAudit: func(obj json.RawMessage, peer listen.Peer) (model.Event, bool) {
			return wafAuditEvent(n, obj, peer)
		},
		EmitBatch: func(_ context.Context, batch []model.Event) error {
			events = append(events, batch...)
			return nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Header.Set("X-Argus-Token", "waf-contract-token")
	req.Header.Set("X-Forwarded-For", "198.51.100.250")
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST %s: status=%d body=%s", path, rec.Code, rec.Body.String())
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || ack.Accepted != len(events) {
		t.Fatalf("ack=%s events=%d error=%v", rec.Body.String(), len(events), err)
	}
	return events
}

func wafAuditJSON(t *testing.T, serverID, hostIP, host string) string {
	t.Helper()
	obj := map[string]any{
		"transaction": map[string]any{
			"client_ip": "198.51.100.77", "server_id": serverID, "host_ip": hostIP,
			"request":  map[string]any{"method": "GET", "uri": "/.git/config", "headers": map[string]string{"Host": host}},
			"response": map[string]int{"http_code": 403},
		},
		"messages": []any{map[string]any{"details": map[string]string{"ruleId": "949110", "msg": "Inbound Anomaly Score Exceeded", "severity": "2"}}},
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWAFHTTPAuditKeepsDistinctTrustedNodes(t *testing.T) {
	want := []string{"10.0.10.11", "10.0.10.12", "10.0.10.13"}
	var objs []string
	for _, ip := range want {
		objs = append(objs, wafAuditJSON(t, "", ip, "attacker.example"))
	}
	for _, format := range []string{"ndjson", "array"} {
		t.Run(format, func(t *testing.T) {
			body := strings.Join(objs, "\n")
			if format == "array" {
				body = "[" + strings.Join(objs, ",") + "]"
			}
			events := wafHTTPBatch(t, "/ingest/modsecurity", body, "203.0.113.50:31000")
			if len(events) != len(want) {
				t.Fatalf("accepted %d events, want %d", len(events), len(want))
			}
			for i, e := range events {
				if e.Node != want[i] || e.DstIP != want[i] || e.Attrs["server_addr"] != want[i] {
					t.Errorf("event %d lost the audit server address: %+v", i, e)
				}
				if e.SourceClass != "waf" || e.Action != "http.attack" || e.SrcIP != "198.51.100.77" || e.Attrs["host"] != "attacker.example" {
					t.Errorf("event %d no longer satisfies the multihost scanner contract: %+v", i, e)
				}
			}
		})
	}
}

func TestWAFHTTPAuditNodeFallbackAndSanitization(t *testing.T) {
	for _, tc := range []struct{ name, serverID, hostIP, want string }{
		{"operator server_id", "waf-01", "10.0.10.11", "waf-01"},
		{"peer fallback", "", "", "2001:db8::50"},
		{"clean server_id", "waf\x1b[31m-01\x1b[0m\x00", "10.0.10.11", "waf-01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := wafHTTPBatch(t, "/ingest/modsecurity", wafAuditJSON(t, tc.serverID, tc.hostIP, "203.0.113.99"), "[2001:db8::50]:31000")
			if len(events) != 1 || events[0].Node != tc.want {
				t.Fatalf("want node %q, events=%+v", tc.want, events)
			}
		})
	}
}

func modSecurityError(prefix, host string) string {
	return prefix + ` [client 198.51.100.77] ModSecurity: Access denied with code 403 (phase 2). [file "/crs.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded"] [severity "2"] [hostname "` + host + `"] [uri "/.env"]`
}

// Host is client-controlled even when it looks like an IP. Three chosen Host
// values on one WAF must not manufacture three nodes for the autoblock rule.
func TestWAFModSecurityNumericHostNeverBecomesNode(t *testing.T) {
	for _, prefix := range []string{
		"2026/10/30 12:00:03 [error] 31#31: *7",
		"[Fri Oct 30 12:00:03.000000 2026] [security2:error] [pid 31:tid 31]",
	} {
		for _, host := range []string{"attacker.example", "203.0.113.11", "203.0.113.12:8443", "[2001:db8::13]:443"} {
			t.Run(fmt.Sprintf("%s/%s", prefix, host), func(t *testing.T) {
				line := modSecurityError(prefix, host)
				events := wafHTTPBatch(t, "/ingest/syslog", line, "10.0.0.7:31000")
				if len(events) != 1 {
					t.Fatalf("accepted %d events, want 1", len(events))
				}
				if e := events[0]; e.Node != "10.0.0.7" || e.DstIP != "" || e.Attrs["server_addr"] != "" || e.Attrs["http_host"] != host {
					t.Fatalf("client Host became trusted server identity: %+v", e)
				}
				for _, tc := range []struct{ line, configured, want string }{
					{line, "waf-from-config", "waf-from-config"},
					{`<134>1 2026-10-30T12:00:03Z waf-from-syslog nginx - - - ` + line, "waf-from-config", "waf-from-syslog"},
				} {
					e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, tc.line, listen.Peer{Addr: "10.0.0.7", Node: tc.configured})
					if !ok || e.Node != tc.want || e.Attrs["http_host"] != host {
						t.Fatalf("trusted node precedence: ok=%v want=%q event=%+v", ok, tc.want, e)
					}
				}
			})
		}
	}
}

func TestWAFHTTPStructuredDataTrustAndSanitization(t *testing.T) {
	host := "waf\x1b[31m" + strings.Repeat("h", model.MaxFieldLen)
	value := "\x1b]8;;http://invalid\x07" + strings.Repeat("я", 200)
	var fields []string
	for _, key := range []string{"container", "pod", "service", "namespace"} {
		fields = append(fields, key+`="`+value+`"`)
	}
	sd := `[argus ` + strings.Join(fields, " ") + ` peer_cn="forged-cn" peer="198.51.100.99" scope="internal" transport="tls" server_addr="10.9.9.9" arbitrary="forged"]`
	line := `<134>1 2026-10-30T12:00:03Z ` + host + ` nginx - - ` + sd + ` ` + modSecurityError("nginx", "attacker.example")
	events := wafHTTPBatch(t, "/ingest/syslog", line, "10.0.0.7:31000")
	if len(events) != 1 {
		t.Fatalf("accepted %d events, want 1", len(events))
	}
	e := events[0]
	if len(e.Node) != model.MaxFieldLen || !strings.HasPrefix(e.Node, "wafhhh") || strings.ContainsAny(e.Node, "\x1b\x07") || e.Attrs["truncated"] != "1" {
		t.Fatalf("late node write was not sanitized: length=%d truncated=%q", len(e.Node), e.Attrs["truncated"])
	}
	for _, key := range []string{"container", "pod", "service", "namespace"} {
		if got := e.Attrs[key]; got != strings.Repeat("я", 126) || !utf8.ValidString(got) {
			t.Errorf("SD %s is not clean, UTF-8 safe and bounded to 253 bytes: %q", key, got)
		}
	}
	if e.Attrs["peer"] != "10.0.0.7" {
		t.Errorf("peer came from payload/header: %q", e.Attrs["peer"])
	}
	for _, key := range []string{"peer_cn", "scope", "transport", "server_addr", "arbitrary"} {
		if got := e.Attrs[key]; got != "" {
			t.Errorf("untrusted SD field %s survived: %q", key, got)
		}
	}
}
