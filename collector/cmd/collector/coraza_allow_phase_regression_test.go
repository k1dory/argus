package main

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

// allow:phase only skips the current phase; allow:request still permits
// response rules to deny. ErrorLog uses "Access allowed" for all allow forms.
// https://coraza.io/docs/seclang/actions/#allow
// https://github.com/corazawaf/coraza/blob/v3.8.1/internal/corazarules/rule_match.go
func TestCorazaPartialAllowDoesNotEmitFinalTransaction(t *testing.T) {
	for _, tc := range []struct {
		name      string
		denyPhase int
	}{
		{"allow_phase_then_request_deny", 2},
		{"allow_request_then_response_deny", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Minimal rule setup: a logged allow:phase (or allow:request) in
			// phase 1, followed by a logged deny in the indicated later phase.
			lines := []string{
				`[client "203.0.113.50"] Coraza: Access allowed (phase 1). Skip early checks [file "/etc/coraza/local.conf"] [id "1001"] [msg "Skip early checks"] [severity "notice"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "same-transaction"]`,
				fmt.Sprintf(`[client "203.0.113.50"] Coraza: Access denied (phase %d). Reject transaction [file "/etc/coraza/local.conf"] [id "1002"] [msg "Reject transaction"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "same-transaction"]`, tc.denyPhase),
			}
			var events []model.Event
			for _, line := range lines {
				e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{Addr: "192.0.2.10", Node: "waf-01", Transport: "file"})
				if ok {
					events = append(events, e)
				}
			}
			if len(events) != 1 {
				t.Fatalf("one denied transaction emitted %d final events; the phase-local allow must not count as another attack: %+v", len(events), events)
			}
			if e := events[0]; e.Outcome != "deny" || e.SessionID != "same-transaction" || e.Attrs["rule_ids"] != "1002" {
				t.Fatalf("lost final deny decision: %+v", e)
			}
		})
	}
}
