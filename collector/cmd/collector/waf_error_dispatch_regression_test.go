package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Request-derived text must not choose the outer log format. This uses the
// real ingestion route: calling ParseWAFErrorLine directly misses the earlier
// CEF/LEEF dispatch. URI markers also occur in ordinary CRS final-deny logs;
// a local rule using msg/logdata macros can emit the other fixtures:
// SecRule REQUEST_HEADERS:X-Fixture "@rx ." "id:1001,phase:2,deny,log,msg:'Header %{MATCHED_VAR}',logdata:'%{MATCHED_VAR}',severity:'WARNING',tag:'attack-protocol'"
func TestPR16WAFRequestDataCannotSelectAnotherParser(t *testing.T) {
	for _, tc := range []struct{ name, msg, data, uri string }{
		{"ordinary", "Header policy", "fixture", "/account"},
		{"uri_cef_marker", "Header policy", "fixture", "/account/CEF:"},
		{"uri_leef_marker", "Header policy", "fixture", "/account/LEEF:"},
		{"message_cef_marker", "Header CEF:", "fixture", "/account"},
		{"message_leef_marker", "Header LEEF:", "fixture", "/account"},
		{"data_cef_event", "Header policy", "CEF:0|Check Point|Firewall|1|100|deny|10|src=198.51.100.99 dvchost=forged-node act=deny unused=fixture", "/account"},
		{"data_leef_event", "Header policy", "LEEF:2.0|UserGate|NGFW|1|100|^|src=198.51.100.99^devName=forged-node^action=deny^unused=fixture", "/account"},
	} {
		for _, format := range []string{"coraza_text", "coraza_caddy", "coraza_syslog_caddy", "modsecurity_nginx"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				// Coraza 3.8.1 ErrorLog writes the leading message verbatim,
				// then quotes the metadata with %q, including the URI and data.
				line := fmt.Sprintf(`[client "203.0.113.50"] Coraza: Access denied (phase 2). %s [file "/etc/coraza/local.conf"] [line "1"] [id "1001"] [rev ""] [msg %q] [data %q] [severity "warning"] [ver ""] [maturity "0"] [accuracy "0"] [tag "attack-protocol"] [hostname "192.0.2.10"] [uri %q] [unique_id "dispatch-boundary"]`, tc.msg, tc.msg, tc.data, tc.uri)
				wantSource, wantNode := "waf.coraza", "192.0.2.10"
				if format == "modsecurity_nginx" {
					// These ASCII payloads contain no quotes or backslashes;
					// ModSecurity's toHexIfNeeded leaves them unchanged too.
					line = fmt.Sprintf(`2026/10/29 17:39:38 [error] 31#31: *7 [client 203.0.113.50] ModSecurity: Access denied with code 403 (phase 2). Matched. [file "/etc/modsecurity/local.conf"] [line "1"] [id "1001"] [msg %q] [data %q] [severity "4"] [tag "attack-protocol"] [hostname "shop.example"] [uri %q] [unique_id "dispatch-boundary"]`, tc.msg, tc.data, tc.uri)
					wantSource = "waf.modsecurity"
				}
				if w, ok := parse.ParseWAFErrorLine(line); !ok || !w.Final || !w.Blocked || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
					t.Fatalf("fixture is not a valid final WAF denial: ok=%v waf=%+v", ok, w)
				}
				if format == "coraza_caddy" || format == "coraza_syslog_caddy" {
					body, err := json.Marshal(map[string]any{"level": "warn", "logger": "http.handlers.waf", "msg": line})
					if err != nil {
						t.Fatal(err)
					}
					line = string(body)
				}
				if format == "coraza_syslog_caddy" {
					line = `<134>1 2026-10-29T17:39:38Z waf-01 caddy - - - ` + line
					wantNode = "waf-01"
				}
				events := wafHTTPBatch(t, "/ingest/syslog", line, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("accepted %d events, want the one WAF denial", len(events))
				}
				e := events[0]
				if e.Source != wantSource || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["rule_ids"] != "1001" {
					t.Errorf("request text replaced a final WAF denial with another log format: source=%q class=%q action=%q outcome=%q rule_ids=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.Attrs["rule_ids"])
				}
				if e.SrcIP != "203.0.113.50" || e.Node != wantNode || e.SessionID != "dispatch-boundary" {
					t.Errorf("request text replaced WAF identity: src_ip=%q node=%q session=%q; want 203.0.113.50/%s/dispatch-boundary", e.SrcIP, e.Node, e.SessionID, wantNode)
				}
			})
		}
	}
}
