package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// A syslog forwarder must not change the meaning of Caddy's decoded msg.
// In particular, dispatch has to inspect MSG before deciding whether JSON
// contains a WAF record. Checking the complete syslog line first misses a
// JSON-escaped marker, even though ParseWAFErrorLine accepts the payload.
func TestPR16Round5EscapedCaddyMarkerSurvivesSyslog(t *testing.T) {
	for _, decision := range []struct {
		name, marker, ruleID string
		final                bool
	}{
		{"deny", "Access denied", "1001", true},
		{"partial_allow", "Access allowed", "949110", false},
	} {
		msg := fmt.Sprintf(`[client "203.0.113.50"] Coraza: %s (phase 2). Header policy [file "/etc/coraza/local.conf"] [id %q] [msg "Header policy"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "round5-escaped"]`, decision.marker, decision.ruleID)
		body, err := json.Marshal(map[string]string{"logger": "http.handlers.waf", "msg": msg})
		if err != nil {
			t.Fatal(err)
		}
		for _, encoding := range []struct{ name, body string }{
			{"literal_control", string(body)},
			{"escaped_space", strings.Replace(string(body), "Coraza: ", `Coraza:\u0020`, 1)},
		} {
			if w, ok := parse.ParseWAFErrorLine(encoding.body); !ok || w.Final != decision.final || len(w.Rules) != 1 || w.Rules[0].ID != decision.ruleID {
				t.Fatalf("invalid Caddy fixture: ok=%v waf=%+v", ok, w)
			}
			for _, envelope := range []struct{ name, prefix, node string }{
				{"raw_control", "", "192.0.2.10"},
				{"rfc3164", "<134>Nov  1 12:00:00 waf-01 caddy[42]: ", "waf-01"},
				{"rfc5424", "<134>1 2026-11-01T12:00:00Z waf-01 caddy 42 - - ", "waf-01"},
			} {
				t.Run(decision.name+"/"+encoding.name+"/"+envelope.name, func(t *testing.T) {
					events := wafHTTPBatchAs(t, "/ingest/syslog", envelope.prefix+encoding.body, "192.0.2.10:31000", parse.FormatWAFCoraza)
					if !decision.final {
						if len(events) != 0 {
							t.Errorf("intermediate allow emitted %d events after adding a syslog envelope: %+v", len(events), events)
						}
						return
					}
					if len(events) != 1 {
						t.Fatalf("accepted=%d, want one WAF denial", len(events))
					}
					e := events[0]
					if e.Source != "waf.coraza" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["rule_ids"] != decision.ruleID {
						t.Errorf("syslog envelope hid decoded Caddy denial: source=%q class=%q action=%q outcome=%q rule_ids=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.Attrs["rule_ids"])
					}
					if e.Node != envelope.node || e.SrcIP != "203.0.113.50" || e.SessionID != "round5-escaped" {
						t.Errorf("lost WAF identity: node=%q src=%q session=%q", e.Node, e.SrcIP, e.SessionID)
					}
				})
			}
		}
	}
}
