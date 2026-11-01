package normalize

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// A legal local rule can expand a request header into its message:
// SecRule REQUEST_HEADERS:X-Fixture "@rx ." "id:1001,phase:1,pass,log,msg:'Header %{MATCHED_VAR}',logdata:'%{MATCHED_VAR}',severity:'WARNING',tag:'attack-protocol'"
// Coraza ErrorLog writes that message verbatim before the real [file ...],
// then writes metadata with %q (including a second, escaped copy of msg).
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazarules/rule_match.go
func TestCorazaAuditMessageCannotInjectRuleCategories(t *testing.T) {
	for _, tc := range []struct{ name, header string }{
		{"ordinary_header", "fixture"},
		{"forged_file_and_tag", `[file "/attacker.conf"] [tag "attack-rce"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := "Header " + tc.header
			line := fmt.Sprintf(`[client "203.0.113.50"] Coraza: Warning. %s [file %q] [line "1"] [id "1001"] [rev ""] [msg %q] [data %q] [severity "warning"] [ver ""] [maturity "0"] [accuracy "0"] [tag "attack-protocol"] [hostname ""] [uri "/"] [unique_id "metadata-fixture"]`,
				msg, "/etc/coraza/header-policy.conf", msg, tc.header)
			body, err := json.Marshal(map[string]any{
				"transaction": map[string]any{
					"client_ip": "203.0.113.50", "is_interrupted": false,
					"producer": map[string]any{"rule_engine": "On"},
					"request": map[string]any{
						"method": "GET", "uri": "/",
						"headers": map[string][]string{"x-fixture": {tc.header}},
					},
				},
				"messages": []any{map[string]any{"data": nil, "error_message": line}},
			})
			if err != nil {
				t.Fatal(err)
			}
			w, ok := parse.ParseWAFAudit(body)
			if !ok {
				t.Fatal("valid Coraza 3.8 audit was rejected")
			}
			e := (&Normalizer{}).FromWAF(w, string(body))
			if e.Attrs["rule_ids"] != "1001" || e.Severity != 5 || e.Outcome != "allow" {
				t.Fatalf("trusted rule or decision changed: %+v", e)
			}
			if e.Attrs["category"] != "protocol" || e.Attrs["categories"] != "protocol" {
				t.Errorf("request header injected trusted categories: category=%q categories=%q, want protocol only",
					e.Attrs["category"], e.Attrs["categories"])
			}
		})
	}
}
