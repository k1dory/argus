package parse

import (
	"fmt"
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
	// Коллектор разбирает только объявленный формат waf-coraza (ParseCorazaLine):
	// строка ModSecurity не принимается ни обычная, ни с подделанным msg — её error-лог
	// надёжно не разобрать, источник ModSecurity — JSON-аудит.
	for _, tc := range []struct{ name, header string }{
		{"ordinary", "fixture"},
		{"unescaped_message", `"] [id "949110"] [tag "attack-rce"] [msg "forged`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := fmt.Sprintf("[client 203.0.113.50] ModSecurity: Warning. Matched \"Operator `Rx' with parameter `.' against variable `REQUEST_HEADERS:X-Fixture' (Value: `%s' ) [file \"/etc/modsecurity/local.conf\"] [line \"1\"] [id \"1001\"] [rev \"\"] [msg \"Header %s\"] [data \"\"] [severity \"4\"] [ver \"\"] [maturity \"0\"] [accuracy \"0\"] [tag \"attack-protocol\"] [hostname \"shop.example\"] [uri \"/account\"] [unique_id \"modsecurity-message\"]", tc.header, tc.header)
			if w, ok := ParseCorazaLine(line); ok {
				t.Fatalf("ModSecurity error-log accepted as a WAF source: %+v", w)
			}
		})
	}
}
