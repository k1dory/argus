package parse

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

// These fixtures follow Coraza v3.8.0 (19b86824f5e97eba72b289a81d5b3c1260292ff0):
// https://github.com/corazawaf/coraza/blob/v3.8.0/internal/corazarules/rule_match.go#L299-L312
// https://github.com/corazawaf/coraza/blob/v3.8.0/internal/corazawaf/transaction.go#L1646-L1654
// Audit part H without K stores ErrorLog() in error_message with data:null.
// drop/redirect call Interrupt; allow only changes AllowType. In DetectionOnly,
// no actual interruption occurs and ErrorLog() uses the Warning marker.
func TestCorazaAuditActionMetadataRegression(t *testing.T) {
	drop := corazaActionRegressionMessage("Access dropped (phase 2).", "1001", "Drop matching request")
	redirect := corazaActionRegressionMessage("Access redirected (phase 2).", "1002", "Redirect matching request")
	allow := corazaActionRegressionMessage("Access allowed (phase 2).", "1003", "Allow trusted client")
	warning := corazaActionRegressionMessage("Warning.", "1004", "Log matched request")

	for _, tc := range []struct {
		name        string
		mode        string
		interrupted bool
		status      int
		messages    []string
		wantIDs     []string
		wantBlocked bool
	}{
		{
			name: "dropped_without_response", mode: "On", interrupted: true,
			messages: []string{drop}, wantIDs: []string{"1001"}, wantBlocked: true,
		},
		{
			name: "redirected_without_response", mode: "On", interrupted: true,
			messages: []string{redirect}, wantIDs: []string{"1002"}, wantBlocked: true,
		},
		{
			name: "allowed_application_403", mode: "On", status: 403,
			messages: []string{allow}, wantIDs: []string{"1003"},
		},
		{
			name: "warning_before_drop", mode: "On", interrupted: true,
			messages: []string{warning, drop}, wantIDs: []string{"1004", "1001"}, wantBlocked: true,
		},
		{
			// Logging-phase warnings may follow the interruption; they must not
			// erase either its rule ID or its blocked outcome.
			name: "warning_after_drop", mode: "On", interrupted: true,
			messages: []string{drop, warning}, wantIDs: []string{"1001", "1004"}, wantBlocked: true,
		},
		{
			name: "detection_only_drop_rule", mode: "DetectionOnly", status: 403,
			messages: []string{corazaActionRegressionMessage("Warning.", "1001", "Drop matching request")},
			wantIDs:  []string{"1001"},
		},
		{
			name: "detection_only_redirect_rule", mode: "DetectionOnly", status: 200,
			messages: []string{corazaActionRegressionMessage("Warning.", "1002", "Redirect matching request")},
			wantIDs:  []string{"1002"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := corazaActionRegressionAudit(t, tc.mode, tc.interrupted, tc.status, tc.messages)
			w, ok := ParseWAFAudit(payload)
			if !ok {
				t.Fatal("valid Coraza audit was not parsed")
			}
			if w.Product != "coraza" || !w.Final || w.Status != tc.status {
				t.Errorf("audit metadata: product=%q final=%v status=%d; want coraza/true/%d", w.Product, w.Final, w.Status, tc.status)
			}
			if w.Blocked != tc.wantBlocked {
				t.Errorf("blocked=%v, want %v (mode=%s is_interrupted=%v)", w.Blocked, tc.wantBlocked, tc.mode, tc.interrupted)
			}
			ids := make([]string, len(w.Rules))
			for i, rule := range w.Rules {
				ids[i] = rule.ID
			}
			if !reflect.DeepEqual(ids, tc.wantIDs) {
				t.Errorf("rule IDs=%q, want %q; all action messages must retain their metadata", ids, tc.wantIDs)
			}
		})
	}
}

func TestCorazaErrorLogBlockingActionsRegression(t *testing.T) {
	for _, tc := range []struct {
		name   string
		marker string
	}{
		{name: "drop", marker: "Access dropped (phase 2)."},
		{name: "redirect", marker: "Access redirected (phase 2)."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := corazaActionRegressionMessage(tc.marker, "1001", "Interrupt matching request")
			w, ok := ParseWAFErrorLine(line)
			if !ok {
				t.Fatalf("native Coraza %s error-log entry was not parsed", tc.name)
			}
			if !w.Blocked || !w.Final || w.EngineMode != "On" {
				t.Errorf("action=%s blocked=%v final=%v mode=%q; want true/true/On", tc.name, w.Blocked, w.Final, w.EngineMode)
			}
			if w.Product != "coraza" || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
				t.Errorf("action=%s product=%q rules=%+v; want coraza and rule 1001", tc.name, w.Product, w.Rules)
			}
		})
	}
}

func corazaActionRegressionMessage(marker, id, msg string) string {
	return fmt.Sprintf(`[client "203.0.113.9"] Coraza: %s %s [file "/etc/coraza/local.conf"] [line "10"] [id %q] [rev ""] [msg %q] [data ""] [severity "critical"] [ver ""] [maturity "0"] [accuracy "0"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "coraza-actions"]`, marker, msg, id, msg)
}

func corazaActionRegressionAudit(t *testing.T, mode string, interrupted bool, status int, messages []string) []byte {
	t.Helper()
	transaction := map[string]any{
		"client_ip": "203.0.113.9",
		"id":        "coraza-actions",
		"request": map[string]any{
			"method": "GET",
			"uri":    "/account",
		},
		"producer":       map[string]any{"rule_engine": mode},
		"is_interrupted": interrupted,
	}
	if status != 0 {
		transaction["response"] = map[string]any{"status": status}
	}
	auditMessages := make([]map[string]any, len(messages))
	for i, message := range messages {
		auditMessages[i] = map[string]any{
			"actionset":     "",
			"message":       "",
			"error_message": message,
			"data":          nil,
		}
	}
	payload, err := json.Marshal(map[string]any{"transaction": transaction, "messages": auditMessages})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}
