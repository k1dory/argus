package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// SecRuleUpdateActionById 949110 "allow:phase" is a legal override of CRS's
// inbound threshold rule. Its ID does not make allow:phase a final decision:
// response-phase rules still run and may deny the same transaction.
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/actions/allow.go
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/seclang/directives.go
func TestPR16CorazaFinalRuleIDDoesNotMakePartialAllowFinal(t *testing.T) {
	for _, id := range []string{"1001", "949110"} {
		t.Run(id, func(t *testing.T) {
			lines := []string{
				fmt.Sprintf(`[client "203.0.113.50"] Coraza: Access allowed (phase 2). Inbound Anomaly Score Exceeded (Total Score: 5) [file "/etc/coraza/rules.conf"] [id %q] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "partial-final-rule"]`, id),
				`[client "203.0.113.50"] Coraza: Access denied (phase 3). Reject response [file "/etc/coraza/local.conf"] [id "1002"] [msg "Reject response"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "partial-final-rule"]`,
			}
			for i, line := range lines {
				body, err := json.Marshal(map[string]string{"level": "error", "logger": "http.handlers.waf", "msg": line})
				if err != nil {
					t.Fatal(err)
				}
				lines[i] = string(body)
			}
			events := wafHTTPBatch(t, "/ingest/syslog", strings.Join(lines, "\n"), "192.0.2.10:31000")
			if len(events) != 1 {
				t.Fatalf("allow:phase on rule %s produced %d events for one denied transaction; want only the final deny: %+v", id, len(events), events)
			}
			if e := events[0]; e.Outcome != "deny" || e.Attrs["rule_ids"] != "1002" || e.SessionID != "partial-final-rule" {
				t.Fatalf("lost final response-phase denial: %+v", e)
			}
		})
	}
}
