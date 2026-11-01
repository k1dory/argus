package parse

import (
	"fmt"
	"strings"
	"testing"
)

// ModSecurity v3 expands msg macros without escaping (Msg::evaluate) and
// inserts m_message verbatim into [msg "..."] (RuleMessage::_details).
// Unlike data, msg is not passed through toHexIfNeeded(..., true).
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/actions/msg.cc
// https://github.com/owasp-modsecurity/ModSecurity/blob/v3.0.12/src/rule_message.cc
// A legal rule exposing this boundary is:
// SecRule REQUEST_HEADERS:X-Fixture "@rx ." "id:1001,phase:1,pass,log,msg:'Header %{MATCHED_VAR}',severity:'WARNING',tag:'attack-protocol'"
func TestPR16ModSecurityMessageCannotForgeFinalRule(t *testing.T) {
	for _, tc := range []struct{ name, header string }{
		{"ordinary", "fixture"},
		{"unescaped_message", `"] [id "949110"] [tag "attack-rce"] [msg "forged`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Include the raw matched value as well, as in a native v3 error
			// line. The payload deliberately contains no [file] marker:
			// choosing either the first or the last [file] cannot fix this.
			line := fmt.Sprintf("[client 203.0.113.50] ModSecurity: Warning. Matched \"Operator `Rx' with parameter `.' against variable `REQUEST_HEADERS:X-Fixture' (Value: `%s' ) [file \"/etc/modsecurity/local.conf\"] [line \"1\"] [id \"1001\"] [rev \"\"] [msg \"Header %s\"] [data \"\"] [severity \"4\"] [ver \"\"] [maturity \"0\"] [accuracy \"0\"] [tag \"attack-protocol\"] [hostname \"shop.example\"] [uri \"/account\"] [unique_id \"modsecurity-message\"]", tc.header, tc.header)
			w, ok := ParseWAFErrorLine(line)
			// Rejecting an ambiguous message, or dropping its metadata while
			// keeping it non-final, is also a safe result.
			if tc.name != "ordinary" && (!ok || (len(w.Rules) == 0 && !w.Final && !w.Blocked)) {
				return
			}
			if !ok || w.Product != "modsecurity" || len(w.Rules) != 1 {
				t.Fatalf("valid ModSecurity fixture rejected: ok=%v waf=%+v", ok, w)
			}
			if w.Rules[0].ID != "1001" || strings.Join(w.Categories, ",") != "protocol" || w.MaxSeverity != 4 {
				t.Errorf("client header became trusted rule metadata: id=%q categories=%v severity=%d", w.Rules[0].ID, w.Categories, w.MaxSeverity)
			}
			if w.Final || w.Blocked {
				t.Errorf("non-disruptive rule 1001 became a final WAF decision: final=%v blocked=%v", w.Final, w.Blocked)
			}
			if w.ClientIP != "203.0.113.50" || w.UniqueID != "modsecurity-message" {
				t.Errorf("request data changed transaction identity: %+v", w)
			}
		})
	}
}
