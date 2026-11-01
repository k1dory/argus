package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// ParseWAFErrorLine explicitly consumes the decoded msg of a Caddy JSON
// object. Dispatch must use that same payload boundary: extra JSON fields and
// their order cannot turn a recognized Coraza denial into a CEF/LEEF event.
// A forwarder can add request context and reorder fields; the extra field is
// not claimed to be part of Coraza-caddy's default ErrorLog callback.
func TestPR16Round4CaddyJSONContextCannotSelectCEFLEEF(t *testing.T) {
	const logger = `"logger":"http.handlers.waf"`
	for _, marker := range []string{"CEF:", "LEEF:"} {
		wafLine := pr16Round4HeaderRuleLine("coraza", "fixture", "Header policy", "/account")
		msg, err := json.Marshal(wafLine)
		if err != nil {
			t.Fatal(err)
		}
		context, err := json.Marshal("/request-context/" + marker)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, body string }{
			{"ordinary_control", "{" + logger + `,"msg":` + string(msg) + "}"},
			{"context_after_msg_control", "{" + logger + `,"msg":` + string(msg) + `,"request_uri":` + string(context) + "}"},
			{"context_before_msg", "{" + logger + `,"request_uri":` + string(context) + `,"msg":` + string(msg) + "}"},
		} {
			for _, envelope := range []struct{ name, prefix, node string }{
				{"raw_json", "", "192.0.2.10"},
				{"syslog_json", "<134>1 2026-11-01T12:00:00Z waf-01 caddy - - - ", "waf-01"},
			} {
				t.Run(marker+"/"+tc.name+"/"+envelope.name, func(t *testing.T) {
					pr16Round4AssertCaddyDenial(t, tc.body, envelope.prefix, envelope.node)
				})
			}
		}
	}
}

// JSON permits escaping a space as \u0020. This has no effect on msg after
// json.Unmarshal, but raw-string dispatch fails to see the WAF marker and
// accepts CEF/LEEF from the URI instead. No extra JSON fields are required.
func TestPR16Round4CaddyJSONEscapesCannotChangeDispatch(t *testing.T) {
	for _, marker := range []string{"CEF:", "LEEF:"} {
		line := pr16Round4HeaderRuleLine("coraza", "fixture", "Header policy", "/account/"+marker)
		body, err := json.Marshal(map[string]string{"logger": "http.handlers.waf", "msg": line})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct{ name, body string }{
			{"literal_control", string(body)},
			{"escaped_marker_space", strings.Replace(string(body), "Coraza: ", `Coraza:\u0020`, 1)},
		} {
			t.Run(marker+"/"+tc.name, func(t *testing.T) {
				pr16Round4AssertCaddyDenial(t, tc.body, "", "192.0.2.10")
			})
		}
	}
}

func pr16Round4AssertCaddyDenial(t *testing.T, body, prefix, node string) {
	t.Helper()
	if w, ok := parse.ParseWAFErrorLine(body); !ok || !w.Blocked || !w.Final || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
		t.Fatalf("fixture is not a recognized final Caddy/Coraza denial: ok=%v waf=%+v", ok, w)
	}
	events := wafHTTPBatch(t, "/ingest/syslog", prefix+body, "192.0.2.10:31000")
	if len(events) != 1 {
		t.Fatalf("recognized Caddy denial disappeared: events=%+v", events)
	}
	e := events[0]
	if e.Source != "waf.coraza" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["rule_ids"] != "1001" {
		t.Errorf("JSON envelope selected another parser before decoding msg: source=%q class=%q action=%q outcome=%q rule_ids=%q",
			e.Source, e.SourceClass, e.Action, e.Outcome, e.Attrs["rule_ids"])
	}
	if e.Node != node || e.SrcIP != "203.0.113.50" || e.SessionID != "round4-header" {
		t.Errorf("lost WAF identity: node=%q src=%q session=%q", e.Node, e.SrcIP, e.SessionID)
	}
}

func pr16Round4HeaderRuleLine(product, value, msg, uri string) string {
	if product == "coraza" {
		return fmt.Sprintf(`[client "203.0.113.50"] Coraza: Access denied (phase 2). %s [file "/etc/coraza/header.conf"] [line "1"] [id "1001"] [rev ""] [msg %q] [data ""] [severity "critical"] [ver ""] [maturity "0"] [accuracy "0"] [tag "attack-protocol"] [hostname "192.0.2.10"] [uri %q] [unique_id "round4-header"]`, msg, msg, uri)
	}
	return fmt.Sprintf("[client 203.0.113.50] ModSecurity: Access denied with code 403 (phase 2). Matched \"Operator `Rx' with parameter `.' against variable `REQUEST_HEADERS:X-Fixture' (Value: `%s' ) [file \"/etc/modsecurity/header.conf\"] [line \"1\"] [id \"1001\"] [rev \"\"] [msg \"%s\"] [data \"\"] [severity \"2\"] [ver \"\"] [maturity \"0\"] [accuracy \"0\"] [tag \"attack-protocol\"] [hostname \"shop.example\"] [uri \"%s\"] [unique_id \"round4-header\"] [ref \"\"]", value, msg, uri)
}
