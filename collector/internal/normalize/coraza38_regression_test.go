package normalize

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

func TestCoraza38AuditDecisionAndIdentity(t *testing.T) {
	const warning = `[client "203.0.113.50"] Coraza: Warning. Restricted File Access Attempt [file "@owasp_crs/REQUEST-930-APPLICATION-ATTACK-LFI.conf"] [id "930130"] [msg "Restricted File Access Attempt"] [severity "critical"] [tag "attack-lfi"] [hostname "198.51.100.201"] [uri "/config.json"]`
	const denied = `[client "203.0.113.50"] Coraza: Access denied (phase 2). Inbound Anomaly Score Exceeded (Total Score: 5) [file "@owasp_crs/REQUEST-949-BLOCKING-EVALUATION.conf"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "unknown"] [tag "anomaly-evaluation"] [hostname "198.51.100.201"] [uri "/config.json"]`

	for _, tc := range []struct {
		name, mode, message, outcome, ruleIDs string
		interrupted                           bool
		status                                int
	}{
		{name: "interrupted without denied message", mode: "On", message: warning, interrupted: true, outcome: "deny", ruleIDs: "930130"},
		{name: "denied message without interruption flag", mode: "On", message: denied, outcome: "deny", ruleIDs: "949110"},
		{name: "warning without interruption", mode: "On", message: warning, outcome: "allow", ruleIDs: "930130"},
		{name: "DetectionOnly overrides both block signals", mode: "DetectionOnly", message: denied, interrupted: true, outcome: "allow", ruleIDs: "949110"},
		{name: "application 403 without final WAF rule", mode: "On", message: warning, status: 403, outcome: "allow", ruleIDs: "930130"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Coraza 3.8 supplies array headers and error_message with data:null.
			// A missing response status must remain unknown even for a WAF block.
			var status any
			wantStatus := ""
			if tc.status != 0 {
				status, wantStatus = tc.status, strconv.Itoa(tc.status)
			}
			body, err := json.Marshal(map[string]any{
				"transaction": map[string]any{
					"client_ip": "203.0.113.50", "host_ip": "10.0.10.12", "host_port": 443,
					"server_id": "waf-from-operator", "is_interrupted": tc.interrupted,
					"producer": map[string]any{"rule_engine": tc.mode},
					"request": map[string]any{
						"method": "GET", "uri": "/config.json",
						"headers": map[string][]string{
							"host": {"198.51.100.200:8443"}, "user-agent": {"fixture-agent"},
						},
					},
					"response": map[string]any{"status": status},
				},
				"messages": []any{map[string]any{"message": "", "error_message": tc.message, "data": nil}},
			})
			if err != nil {
				t.Fatal(err)
			}
			w, ok := parse.ParseWAFAudit(body)
			if !ok {
				t.Fatal("Coraza 3.8 audit was not accepted")
			}
			e := (&Normalizer{}).FromWAF(w, string(body))
			if e.Source != "waf.coraza" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != tc.outcome {
				t.Fatalf("wrong normalized decision: source=%q class=%q action=%q outcome=%q, want outcome=%q", e.Source, e.SourceClass, e.Action, e.Outcome, tc.outcome)
			}
			if e.Attrs["rule_ids"] != tc.ruleIDs || e.Attrs["engine_mode"] != tc.mode || e.Attrs["status"] != wantStatus {
				t.Fatalf("lost rule/decision metadata: rule_ids=%q engine_mode=%q status=%q", e.Attrs["rule_ids"], e.Attrs["engine_mode"], e.Attrs["status"])
			}
			if e.Attrs["host"] != "198.51.100.200:8443" || e.Attrs["user_agent"] != "fixture-agent" {
				t.Fatalf("array request headers were not retained: host=%q user_agent=%q", e.Attrs["host"], e.Attrs["user_agent"])
			}
			if e.Node != "waf-from-operator" || e.DstIP != "10.0.10.12" || e.Attrs["server_addr"] != "10.0.10.12" || e.SrcIP != "203.0.113.50" {
				t.Fatalf("request Host or error-message metadata replaced trusted identity: node=%q dst_ip=%q server_addr=%q src_ip=%q", e.Node, e.DstIP, e.Attrs["server_addr"], e.SrcIP)
			}
		})
	}
}

func TestCoraza38AuditPreservesUnixTimestamp(t *testing.T) {
	// These time fields come from the anonymized Coraza 3.8 audit fixture.
	// Coraza writes UnixTimestamp_ = tx.Timestamp and renders the local string
	// with time.Unix(0, tx.Timestamp), so the integer is nanoseconds, not seconds:
	// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazawaf/transaction.go#L1558
	const body = `{"transaction":{"timestamp":"2026/10/29 17:39:38","unix_timestamp":1793284778618840706,"client_ip":"203.0.113.50","request":{"method":"GET","uri":"/config.json"},"producer":{"rule_engine":"On"}}}`
	want := time.Unix(0, 1793284778618840706).UTC().Format("2006-01-02 15:04:05.000")
	previousNow := model.Now
	model.Now = func() time.Time { return time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { model.Now = previousNow })

	w, ok := parse.ParseWAFAudit([]byte(body))
	if !ok {
		t.Fatal("Coraza 3.8 audit was not accepted")
	}
	e := (&Normalizer{}).FromWAF(w, body)
	if e.TS != want {
		t.Fatalf("Coraza event time replaced by receive/local time: got %q, want UTC %q from unix_timestamp", e.TS, want)
	}
}
