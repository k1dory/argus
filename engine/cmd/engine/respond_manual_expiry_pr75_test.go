package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
)

// An incident first seen while the address is excluded must not keep that
// exemption after the exclusion ends. After expiry (or revocation), fresh
// trusted evidence for the same open incident must reach the responder — in
// this process and after a restart.
func TestPR75ManualExpiryReconsidersSuppressedIncident(t *testing.T) {
	for _, end := range []string{"expiry", "revoke", "expiry_after_restart"} {
		t.Run(end, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			rule := strings.Replace(capRule(4), "block_cap_window: 1h", "block_cap_window: 72h", 1)
			dir := rulesDirWith(t, map[string]string{"r.yml": rule})
			e := testEngine(t, f, dir, ipsConfig(x.srv), "s", "s")
			ctx := context.Background()
			code, body := do(t, e.handler(), http.MethodPost, "/respond/exclude", "s",
				`{"ip":"203.0.113.7","ttl":"24h","user":"qa","reason":"partner scanner, agreed window"}`)
			if code != http.StatusOK {
				t.Fatalf("fixture: exclude: HTTP %d %s", code, body)
			}
			until, excluded := e.excludedUntil("203.0.113.7", time.Now())
			if !excluded {
				t.Fatal("fixture: expected the exclusion")
			}
			during := until.Add(-time.Minute)
			inc := capInc("INC-2", "203.0.113.7")
			inc.Events[0] = wafEvent(model.FormatTS(during), "203.0.113.7", "file", "")
			e.autoRespond(ctx, []*incidents.Incident{inc}, during)
			if x.blocks.Load() != 0 || keyState(e, "INC-2", "203.0.113.7") != keyExcluded {
				t.Fatalf("the incident must be suppressed while the exclusion is valid: state=%q", keyState(e, "INC-2", "203.0.113.7"))
			}
			after := until.Add(time.Minute)
			switch end {
			case "revoke":
				code, body = do(t, e.handler(), http.MethodPost, "/respond/exclude/revoke", "s", `{"ip":"203.0.113.7","user":"qa","reason":"window over"}`)
				if code != http.StatusOK {
					t.Fatalf("revoke: HTTP %d %s", code, body)
				}
				after = during.Add(time.Second)
				if _, excluded := e.excludedUntil("203.0.113.7", time.Now()); excluded {
					t.Fatal("revoked exclusion still applies")
				}
			case "expiry_after_restart":
				saveJournal(f)
				e = testEngine(t, f, dir, ipsConfig(x.srv), "s", "s")
				e.restoreRespState([]incidents.Incident{*inc}, during)
				if !e.restoreKeys(ctx, during) {
					t.Fatal("journal not read after restart")
				}
				if _, excluded := e.excludedUntil("203.0.113.7", during); !excluded {
					t.Fatal("exclusion lost after restart")
				}
				if keyState(e, "INC-2", "203.0.113.7") != keyExcluded {
					t.Fatalf("excluded key not restored: %q", keyState(e, "INC-2", "203.0.113.7"))
				}
			}
			e.pruneRespState(after, respStateTTL)
			// An update within the rule's dedupe window, not a new incident ID.
			inc.Events = append(inc.Events, wafEvent(model.FormatTS(after), "203.0.113.7", "file", ""))
			inc.EventCount = uint32(len(inc.Events))
			e.autoRespond(ctx, []*incidents.Incident{inc}, after)
			if x.blocks.Load() != 1 || len(e.resp.Active()) != 1 {
				t.Fatalf("ended exclusion still suppresses fresh evidence for the same incident: incident state=%q, key=%q, blocks=%d",
					e.respStatus("INC-2"), keyState(e, "INC-2", "203.0.113.7"), x.blocks.Load())
			}
		})
	}
}
