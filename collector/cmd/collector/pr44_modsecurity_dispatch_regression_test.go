package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Reuse the attack shapes from review/codex-modsec-errorlog under PR #44's
// new contract: ModSecurity error-log is searchable syslog, not WAF input.
// Include ordinary HTTP paths that also match the legacy Jenkins heuristic,
// and request-derived messages containing complete CEF/LEEF records.
func TestPR44ModSecurityCannotFallThroughToVendorParsers(t *testing.T) {
	for _, tc := range []struct{ name, message, uri string }{
		{"ordinary_control", "Header policy", "/account"},
		{"msg_final_rule", `Header "] [id "949110"] [tag "attack-rce"] [msg "forged`, "/account"},
		{"msg_metadata_boundary", `Header "] [severity "2"] [tag "attack-rce"] [hostname "forged.example"] [x "`, "/account"},
		{"uri_tag", "Header policy", `/account"] [tag "attack-rce"] [x "`},
		{"uri_session", "Header policy", `/account"] [unique_id "forged-session"] [x "`},
		{"uri_credentials", "Header policy", "/credentials"},
		{"uri_build", "Header policy", "/build"},
		{"uri_job", "Header policy", "/job/deploy"},
		{"msg_cef", "Header " + pr44CEF + " rule_ids=949110 unused=fixture", "/account"},
		{"msg_leef", "Header " + pr44LEEF + "^rule_ids=949110^unused=fixture", "/account"},
	} {
		// msg and uri are intentionally unescaped, matching the fixtures on
		// the review branch. The transport is never taken from these fields.
		body := fmt.Sprintf(`[client 203.0.113.50] ModSecurity: Access denied with code 403 (phase 2). [file "/etc/modsecurity/local.conf"] [id "1001"] [msg "%s"] [severity "2"] [tag "attack-protocol"] [hostname "shop.example"] [uri "%s"] [unique_id "pr44-modsec"]`, tc.message, tc.uri)
		for _, envelope := range []struct{ name, prefix string }{
			{"raw", ""},
			{"rfc3164", "<134>Nov  1 12:00:00 waf-01 nginx[42]: "},
			{"rfc5424", "<134>1 2026-11-01T12:00:00Z waf-01 nginx 42 - - "},
		} {
			for _, format := range []string{"", parse.FormatCEF, parse.FormatLEEF, parse.FormatWAFCoraza} {
				t.Run(tc.name+"/"+envelope.name+"/format="+format, func(t *testing.T) {
					line := envelope.prefix + body
					events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", format)
					if len(events) != 1 {
						t.Fatalf("error-log must remain one searchable record: got %d", len(events))
					}
					e := events[0]
					if e.SourceClass != "syslog" || !strings.HasPrefix(e.Action, "syslog.") || e.Outcome != "unknown" || e.Attrs["waf_unparsed"] != "1" {
						t.Errorf("request data reclassified ModSecurity: class=%q action=%q outcome=%q waf_unparsed=%q", e.SourceClass, e.Action, e.Outcome, e.Attrs["waf_unparsed"])
					}
					for _, key := range []string{"rule_ids", "category", "categories", "anomaly_score", "engine_mode", "server_addr"} {
						if e.Attrs[key] != "" {
							t.Errorf("error-log supplied trusted metadata %s=%q", key, e.Attrs[key])
						}
					}
					if e.Raw != line {
						t.Error("raw evidence was changed")
					}
				})
			}
		}
	}
}
