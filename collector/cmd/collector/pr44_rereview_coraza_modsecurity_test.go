package main

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Coraza's ErrorLog writes the expanded rule message before the metadata and
// quotes msg/data with %q. Neither representation escapes a colon or a space.
// A rule using msg:'Header %{MATCHED_VAR}' or logdata:'%{MATCHED_VAR}' can therefore
// log this ordinary request-header value without the sender being compromised.
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazarules/rule_match.go
func TestPR44ReReviewCorazaRequestMarkerCannotHideDenial(t *testing.T) {
	for _, tc := range []struct{ name, message, data string }{
		{"control", "Header policy", "fixture"},
		{"expanded_rule_message", "Header ModSecurity: Warning.", "fixture"},
		{"quoted_logdata", "Header policy", "ModSecurity: Warning."},
	} {
		msg := fmt.Sprintf(`[client "203.0.113.50"] Coraza: Access denied (phase 2). %s [file "/etc/coraza/local.conf"] [line "1"] [id "1001"] [rev ""] [msg %q] [data %q] [severity "critical"] [ver ""] [maturity "0"] [accuracy "0"] [tag "attack-protocol"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "pr44-rereview-coraza"]`, tc.message, tc.message, tc.data)
		body, err := json.Marshal(map[string]string{"logger": "http.handlers.waf", "msg": msg})
		if err != nil {
			t.Fatal(err)
		}
		// Establish that the actual declared-format parser accepts the fixture;
		// the regression concerns dispatch before this parser is reached.
		w, ok := parse.ParseCorazaLine(string(body))
		if !ok || !w.Final || !w.Blocked || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
			t.Fatalf("invalid Coraza fixture %s: accepted=%v waf=%+v", tc.name, ok, w)
		}
		for _, envelope := range []struct{ name, prefix, format string }{
			{"raw_json_configured", "", parse.FormatWAFCoraza},
			{"rfc3164_configured", "<134>Nov  1 12:00:00 waf-01 caddy[42]: ", parse.FormatWAFCoraza},
			{"rfc5424_config_over_sd", `<134>1 2026-11-01T12:00:00Z waf-01 caddy 42 - [argus format="cef"] `, parse.FormatWAFCoraza},
			{"authenticated_http_sd", `<134>1 2026-11-01T12:00:00Z waf-01 caddy 42 - [argus format="waf-coraza"] `, ""},
		} {
			t.Run(tc.name+"/"+envelope.name, func(t *testing.T) {
				line := envelope.prefix + string(body)
				events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", envelope.format)
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one final Coraza denial", len(events))
				}
				e := events[0]
				if e.Source != "waf.coraza" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.Attrs["rule_ids"] != "1001" || e.Attrs["waf_unparsed"] != "" {
					t.Errorf("request text hid a trusted WAF denial: source=%q class=%q action=%q outcome=%q rule_ids=%q waf_unparsed=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.Attrs["rule_ids"], e.Attrs["waf_unparsed"])
				}
				if e.SrcIP != "203.0.113.50" || e.SessionID != "pr44-rereview-coraza" || e.Raw != line {
					t.Errorf("lost denial identity/evidence: src=%q session=%q raw_preserved=%v", e.SrcIP, e.SessionID, e.Raw == line)
				}
			})
		}
	}
}
