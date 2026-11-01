package parse

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Coraza 3.8.1 uses %q for metadata, not raw interpolation inside quotes.
// Reproduce its actual serialization so an impossible, unescaped [msg]/[data]
// fixture cannot be mistaken for a remote metadata injection.
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazarules/rule_match.go
func TestPR16CorazaQuotedRequestDataCannotBecomeMetadata(t *testing.T) {
	const forged = `"] [file "/attacker.conf"] [id "949110"] [tag "attack-rce"] [hostname "198.51.100.99"] [unique_id "forged"]`
	for _, field := range []string{"msg", "data"} {
		for _, prefix := range []string{"", `\`, `\\`, `\\\`} {
			t.Run(fmt.Sprintf("%s/backslashes=%d", field, len(prefix)), func(t *testing.T) {
				msg, data := "Header policy", "fixture"
				payload := prefix + forged
				if field == "msg" {
					msg = "Header " + payload
				} else {
					data = payload
				}
				if len(msg) > 280 || len(data) > 280 {
					t.Fatal("fixture exceeds Coraza's log-field truncation limit")
				}
				line := fmt.Sprintf(`[client "203.0.113.50"] Coraza: Warning. %s [file "/etc/coraza/local.conf"] [line "1"] [id "1001"] [rev ""] [msg %q] [data %q] [severity "warning"] [ver ""] [maturity "0"] [accuracy "0"] [tag "attack-protocol"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "quoted-metadata"]`, msg, msg, data)
				caddy, err := json.Marshal(map[string]string{"logger": "http.handlers.waf", "msg": line})
				if err != nil {
					t.Fatal(err)
				}
				for _, format := range []string{"text", "caddy", "audit"} {
					t.Run(format, func(t *testing.T) {
						var w WAF
						var ok bool
						switch format {
						case "text":
							w, ok = ParseWAFErrorLine(line)
						case "caddy":
							w, ok = ParseWAFErrorLine(string(caddy))
						case "audit":
							w, ok = ParseWAFAudit(corazaActionRegressionAudit(t, "On", false, 200, []string{line}))
						}
						if !ok || w.Product != "coraza" || len(w.Rules) != 1 {
							t.Fatalf("valid Coraza fixture rejected: ok=%v waf=%+v", ok, w)
						}
						if w.Rules[0].ID != "1001" || w.MaxSeverity != 4 || strings.Join(w.Categories, ",") != "protocol" {
							t.Errorf("quoted request data became trusted rule metadata: %+v", w)
						}
						if w.Blocked || w.Final != (format == "audit") {
							t.Errorf("quoted request data changed the decision: final=%v blocked=%v", w.Final, w.Blocked)
						}
						if format != "audit" && (w.ClientIP != "203.0.113.50" || w.ServerName != "192.0.2.10" || w.URI != "/account" || w.UniqueID != "quoted-metadata") {
							t.Errorf("quoted request data changed error-log identity: %+v", w)
						}
					})
				}
			})
		}
	}
}
