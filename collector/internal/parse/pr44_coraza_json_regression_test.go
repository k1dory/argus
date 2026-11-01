package parse

import (
	"encoding/json"
	"testing"
)

// waf-coraza is the declared Caddy JSON format. The generic error-log parser
// also supports raw text for other callers, but that must not widen this API.
func TestPR44CorazaFormatRequiresCaddyJSONObject(t *testing.T) {
	const line = `[client "203.0.113.50"] Coraza: Access denied (phase 2). Header policy [file "/etc/coraza/local.conf"] [id "1001"] [msg "Header policy"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "pr44-json"]`
	caddy, err := json.Marshal(map[string]string{"logger": "http.handlers.waf", "msg": line})
	if err != nil {
		t.Fatal(err)
	}
	encodedLine, err := json.Marshal(line)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("caddy_control", func(t *testing.T) {
		w, ok := ParseCorazaLine(string(caddy))
		if !ok || !w.Final || !w.Blocked || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
			t.Fatalf("valid Caddy JSON lost its final denial: accepted=%v waf=%+v", ok, w)
		}
	})
	for _, tc := range []struct{ name, input string }{
		{"bare_coraza_text", line},
		{"unrelated_text_with_marker", "ordinary application message: " + line},
		{"invalid_json", `{"logger":"http.handlers.waf","msg":` + line},
		{"json_string_instead_of_record", string(encodedLine)},
		{"json_array_instead_of_record", "[" + string(encodedLine) + "]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if w, ok := ParseCorazaLine(tc.input); ok {
				t.Fatalf("non-Caddy input accepted as declared waf-coraza: product=%q final=%v blocked=%v rules=%+v", w.Product, w.Final, w.Blocked, w.Rules)
			}
		})
	}
}
