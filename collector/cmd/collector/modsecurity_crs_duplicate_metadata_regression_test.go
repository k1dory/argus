package main

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// RuleMessage::errorLog adds _errorLogTail after _details; both contain
// hostname, uri and unique_id. This is native output, not injected metadata.
// ModSecurity::serverLog uses errorLog on stderr when no callback is installed.
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/rule_message.cc#L23-L85
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/headers/modsecurity/rule_message.h#L160-L162
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/modsecurity.cc#L181-L184
func TestPR16Round3ModSecurityNativeTailRetainsCRSFinalWarning(t *testing.T) {
	for _, crs := range []string{"3.3.5", "4.3.0"} {
		for _, repeatedTail := range []bool{false, true} {
			t.Run(fmt.Sprintf("crs_%s/repeated_tail=%v", crs, repeatedTail), func(t *testing.T) {
				// DetectionOnly still emits the CRS 949110 threshold warning.
				// The collector intentionally accepts that final rule as an attack.
				line := pr16Round3CRSLine(crs, "Warning.", "/account")
				if repeatedTail {
					line = "Server log callback is not set -- " + line +
						` [hostname "192.0.2.10"] [uri "/account"] [unique_id "round3-crs"]`
				}
				events := wafHTTPBatch(t, "/ingest/syslog", line, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("native CRS final warning was discarded: accepted=%d, want 1", len(events))
				}
				e := events[0]
				if e.Source != "waf.modsecurity" || e.Action != "http.attack" || e.Outcome != "allow" || e.Attrs["rule_ids"] != "949110" || e.Attrs["anomaly_score"] != "5" || e.SessionID != "round3-crs" {
					t.Errorf("native repeated tail erased rule metadata: %+v", e)
				}
			})
		}
	}
}

// ModSecurity decodes the URL path before placing it verbatim in [uri "..."]:
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/transaction.cc#L440-L463
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/rule_message.cc#L40-L44
// The complete log uses toHexIfNeeded with its default escape_spec=false;
// printable quotes and brackets in the URI are therefore not escaped.
// An attacker need not control a WAF rule, producer, or authenticated log sender.
func TestPR16Round3ModSecurityURIRepeatedKeyCannotHideDenial(t *testing.T) {
	for _, crs := range []string{"3.3.5", "4.3.0"} {
		for _, tc := range []struct{ name, path string }{
			{"ordinary_control", "/account"},
			{"duplicate_id", `/account"] [id "0"] [x "`},
			{"duplicate_hostname", `/account"] [hostname "untrusted.example"] [x "`},
		} {
			t.Run(crs+"/"+tc.name, func(t *testing.T) {
				path := pr16Round3DecodedHTTPPath(t, tc.path)
				line := pr16Round3CRSLine(crs, "Access denied with code 403 (phase 2).", path)
				events := wafHTTPBatch(t, "/ingest/syslog", line, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("a real WAF denial must survive ambiguous client data: events=%+v", events)
				}
				e := events[0]
				// Discarding untrusted rule details is acceptable, but the
				// trusted denial must still match rules/waf-*.yml's selection.
				if e.Source != "waf.modsecurity" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.SrcIP != "203.0.113.50" {
					t.Errorf("client URI hid a final denial from WAF correlations: source=%q class=%q action=%q outcome=%q src=%q rule_ids=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.SrcIP, e.Attrs["rule_ids"])
				}
			})
		}
	}
}

// Build the native serialization of CRS 949110 in both supported major
// rulesets. The URI is deliberately %s, not %q: the upstream emitter does not
// quote it. All other fields below are trusted engine/ruleset data.
// https://github.com/coreruleset/coreruleset/blob/v3.3.5/rules/REQUEST-949-BLOCKING-EVALUATION.conf#L75-L88
// https://github.com/coreruleset/coreruleset/blob/v4.3.0/rules/REQUEST-949-BLOCKING-EVALUATION.conf
func pr16Round3CRSLine(crs, marker, path string) string {
	variable, severity, lineNo := "TX:ANOMALY_SCORE", "2", "75"
	tags := `[tag "application-multi"] [tag "language-multi"] [tag "platform-multi"] [tag "attack-generic"]`
	if strings.HasPrefix(crs, "4.") {
		variable, severity, lineNo = "TX:BLOCKING_INBOUND_ANOMALY_SCORE", "0", "222"
		tags = `[tag "anomaly-evaluation"] [tag "OWASP_CRS"]`
	}
	return fmt.Sprintf("[client 203.0.113.50] ModSecurity: %s Matched \"Operator `Ge' with parameter `5' against variable `%s' (Value: `5' ) [file \"/etc/modsecurity/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf\"] [line \"%s\"] [id \"949110\"] [rev \"\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 5)\"] [data \"\"] [severity \"%s\"] [ver \"OWASP_CRS/%s\"] [maturity \"0\"] [accuracy \"0\"] %s [hostname \"192.0.2.10\"] [uri \"%s\"] [unique_id \"round3-crs\"] [ref \"\"]", marker, variable, lineNo, severity, crs, tags, path)
}

func pr16Round3DecodedHTTPPath(t *testing.T, path string) string {
	t.Helper()
	if len(path) > 200 {
		t.Fatal("fixture exceeds ModSecurity's logged URI limit")
	}
	// Carry the payload in a percent-encoded HTTP request target. The SQLi
	// query represents an independent CRS match contributing to the score;
	// it is not included in ModSecurity's decoded, query-free [uri] field.
	target := (&url.URL{Path: path, RawQuery: "id=1%27%20OR%201%3D1--"}).RequestURI()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader("GET " + target + " HTTP/1.1\r\nHost: shop.example\r\n\r\n")))
	if err != nil {
		t.Fatalf("fixture is not a valid HTTP request: %v", err)
	}
	defer req.Body.Close()
	decoded, err := url.PathUnescape(strings.SplitN(req.RequestURI, "?", 2)[0])
	if err != nil || decoded != path {
		t.Fatalf("request path round trip: decoded=%q, want=%q, error=%v", decoded, path, err)
	}
	return decoded
}
