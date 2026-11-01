package main

import (
	"encoding/json"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Context added by a log forwarder remains JSON data, including spaces in a
// client User-Agent. Prepending a synthetic PRI must not turn that first space
// into a syslog HOSTNAME/MSG boundary. This uses the same enriched Caddy input
// supported by TestPR16Round4CaddyJSONContextCannotSelectCEFLEEF; the context is
// not asserted to be part of coraza-caddy's default error callback.
func TestPR16Round5CaddyContextSpaceCannotSelectCEFLEEF(t *testing.T) {
	const msg = `[client "203.0.113.50"] Coraza: Access denied (phase 2). Header policy [file "/etc/coraza/local.conf"] [id "1001"] [msg "Header policy"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "round5-json-space"]`
	for _, format := range []struct{ name, payload string }{
		{"cef", "CEF:0|Check Point|Firewall|1|100|allow|1|src=198.51.100.99 dvchost=forged-node act=allow unused=fixture"},
		{"leef", "LEEF:2.0|UserGate|NGFW|1|100|^|src=198.51.100.99^devName=forged-node^action=allow^unused=fixture"},
	} {
		for _, context := range []struct{ name, prefix string }{
			{"no_space_control", "Fixture/1.0/"},
			{"space_before_marker", "Fixture/1.0 "},
		} {
			// Struct field order deliberately places request context before msg.
			body, err := json.Marshal(struct {
				UserAgent string `json:"request_user_agent"`
				Logger    string `json:"logger"`
				Msg       string `json:"msg"`
			}{context.prefix + format.payload, "http.handlers.waf", msg})
			if err != nil {
				t.Fatal(err)
			}
			if w, ok := parse.ParseWAFErrorLine(string(body)); !ok || !w.Final || !w.Blocked || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
				t.Fatalf("invalid Caddy fixture: ok=%v waf=%+v", ok, w)
			}
			for _, envelope := range []struct{ name, prefix, node string }{
				{"raw_json", "", "192.0.2.10"},
				{"rfc3164_control", "<134>Nov  1 12:00:00 waf-01 caddy[42]: ", "waf-01"},
				{"rfc5424_control", "<134>1 2026-11-01T12:00:00Z waf-01 caddy 42 - - ", "waf-01"},
			} {
				t.Run(format.name+"/"+context.name+"/"+envelope.name, func(t *testing.T) {
					line := envelope.prefix + string(body)
					// Формат объявлен источником (waf-coraza): «CEF:»/«LEEF:» в данных
					// клиента не выбирают разборщик — выбор не зависит от содержимого.
					events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.10:31000", parse.FormatWAFCoraza)
					if len(events) != 1 {
						t.Fatalf("accepted=%d, want one WAF denial", len(events))
					}
					e := events[0]
					if e.Source != "waf.coraza" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["rule_ids"] != "1001" {
						t.Errorf("client context replaced WAF decision: source=%q class=%q action=%q outcome=%q rule_ids=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.Attrs["rule_ids"])
					}
					if e.Node != envelope.node || e.SrcIP != "203.0.113.50" || e.SessionID != "round5-json-space" {
						t.Errorf("client context replaced WAF identity: node=%q src=%q session=%q", e.Node, e.SrcIP, e.SessionID)
					}
				})
			}
		}
	}
}
