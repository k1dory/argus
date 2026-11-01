package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

// PR #80 trusts collector.clock_skew/transport=internal and groups by peer.
// An ingest-token holder must not make the collector attest to another peer's
// clock. Exercise the real HTTP parser and skew watcher without opening sockets.
// The batch callback supplies the same transport overwrite as emitHTTPBatch in
// main.go; unrelated ASN enrichment and the durable sink are outside this check.
func TestPR80ClockSkewIngestCannotAttributeSkewToAnotherPeer(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	previousNow := model.Now
	model.Now = func() time.Time { return now }
	t.Cleanup(func() { model.Now = previousNow })

	const sender = "198.51.100.40"
	const victim = "192.0.2.10"
	const token = "pr80-dummy-ingest-token"
	future := now.Add(30 * time.Minute)
	payload, err := json.Marshal(model.Event{
		TS: model.FormatTS(future), Source: "fixture.integration", Action: "fixture.event",
		Attrs: map[string]string{"peer": victim, "transport": "internal"},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path, body string
	}{
		{
			name: "syslog_control", path: "/ingest/syslog",
			body: `<134>1 ` + future.Format(time.RFC3339) + ` fixture-host fixture-app - - [argus peer="` + victim + `" transport="internal"] fixture event`,
		},
		{name: "normalized_events", path: "/ingest/events", body: string(payload)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := newSkewWatch(10 * time.Minute)
			var accepted []model.Event
			h := &listen.HTTPHandlers{
				Token: token,
				ParseLine: func(line string, peer listen.Peer) (model.Event, bool) {
					return parseSyslogLine(&normalize.Normalizer{}, nil, line, peer)
				},
				EmitBatch: func(_ context.Context, events []model.Event) error {
					for i := range events {
						if events[i].Attrs == nil {
							events[i].Attrs = map[string]string{}
						}
						events[i].Attrs["transport"] = "http"
						watch.apply(&events[i], now)
					}
					accepted = append(accepted, events...)
					return nil
				},
			}
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
			req.RemoteAddr = sender + ":40000"
			req.Header.Set("X-Argus-Token", token)
			recorder := httptest.NewRecorder()
			h.Mux().ServeHTTP(recorder, req)
			if recorder.Code != http.StatusAccepted || len(accepted) != 1 {
				t.Fatalf("ingest: status=%d accepted=%d body=%s", recorder.Code, len(accepted), recorder.Body.String())
			}
			if accepted[0].Attrs["transport"] != "http" || accepted[0].TS != model.FormatTS(now) {
				t.Fatalf("fixture must traverse the HTTP transport stamp and timestamp correction: %+v", accepted[0])
			}
			summaries := watch.flush(now.Add(time.Minute))
			if len(summaries) != 1 {
				t.Fatalf("want one clock-skew summary, got %d", len(summaries))
			}
			signal := summaries[0]
			if signal.Source != "argus.collector" || signal.Action != "collector.clock_skew" || signal.Attrs["transport"] != "internal" {
				t.Fatalf("fixture must reach the internal telemetry selected by a41c-ops-067: %+v", signal)
			}
			if got := signal.Attrs["peer"]; got != sender {
				t.Fatalf("sender %s supplied peer=%s; collector emitted trusted clock-skew telemetry for %q, want the actual sender %q", sender, victim, got, sender)
			}
		})
	}
}
