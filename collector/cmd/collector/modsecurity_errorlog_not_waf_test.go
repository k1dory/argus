package main

import (
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Error-лог ModSecurity — не источник WAF (ревью codex #16, раунды 2–5): msg и uri в
// нём не экранированы, и данные запроса подделывают метаданные правила и решение.
// Строка остаётся событием syslog (по ней есть поиск) с attrs.waf_unparsed=1, но не
// кормит корреляции WAF: не http.attack, без rule_ids, без outcome deny/allow. Это не
// зависит от объявленного формата — ModSecurity объявить нельзя, источник — JSON-аудит.
func TestModSecurityErrorLogIsNotWAFSource(t *testing.T) {
	lines := map[string]string{
		"denial":      `[client 203.0.113.50] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`Rx'" + ` with parameter ` + "`.'" + ` against variable ` + "`REQUEST_HEADERS:X-Fixture'" + ` [file "/etc/modsecurity/local.conf"] [line "1"] [id "1001"] [msg "Header policy"] [severity "2"] [tag "attack-protocol"] [hostname "shop.example"] [uri "/account"] [unique_id "modsec-denial"]`,
		"crs_anomaly": `[client 203.0.113.51] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator ` + "`Ge'" + ` with parameter ` + "`5'" + ` against variable ` + "`TX:BLOCKING_INBOUND_ANOMALY_SCORE'" + ` [file "/etc/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "0"] [tag "anomaly-evaluation"] [hostname "shop.example"] [uri "/"] [unique_id "modsec-crs"]`,
		"forged_msg":  `[client 203.0.113.52] ModSecurity: Warning. Matched "Operator ` + "`Rx'" + ` with parameter ` + "`.'" + ` against variable ` + "`REQUEST_HEADERS:X-Fixture'" + ` [file "/etc/modsecurity/local.conf"] [line "1"] [id "1001"] [msg "Header "] [id "949110"] [tag "attack-rce"] [msg "forged"] [severity "4"] [hostname "shop.example"] [uri "/account"] [unique_id "modsec-forged"]`,
	}
	envelopes := map[string]string{"raw": "", "rfc3164": "<134>Nov  1 12:00:00 waf-01 nginx[42]: "}
	for name, line := range lines {
		for ename, prefix := range envelopes {
			for _, format := range []string{"", parse.FormatWAFCoraza, parse.FormatCEF} {
				t.Run(name+"/"+ename+"/format="+format, func(t *testing.T) {
					events := wafHTTPBatchAs(t, "/ingest/syslog", prefix+line, "192.0.2.10:31000", format)
					if len(events) != 1 {
						t.Fatalf("ModSecurity line must stay a searchable event, got %d", len(events))
					}
					e := events[0]
					if e.Action == "http.attack" || e.SourceClass == "waf" || e.Attrs["rule_ids"] != "" {
						t.Errorf("ModSecurity error-log fed WAF correlations: action=%q class=%q rule_ids=%q", e.Action, e.SourceClass, e.Attrs["rule_ids"])
					}
					if e.Outcome == "deny" || e.Outcome == "allow" {
						t.Errorf("ModSecurity error-log produced a WAF decision: outcome=%q", e.Outcome)
					}
					if e.Attrs["waf_unparsed"] != "1" {
						t.Errorf("attrs.waf_unparsed=%q, want 1", e.Attrs["waf_unparsed"])
					}
				})
			}
		}
	}
}
