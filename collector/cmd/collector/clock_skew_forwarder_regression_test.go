package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
)

// argus_pipe's Vector sink forwards Authentik, NetBird and local journald
// through one loopback /ingest/events endpoint. The VRL events have distinct
// sources but no attrs.peer. The documented remote Vector path uses Caddy,
// which likewise presents a shared connection address to the collector.
//
// Before the HTTP peer stamp, skewWatch used http:<source> for these events.
// A shared relay address must not merge their clock diagnostics or attribute
// another source's count / maximum skew to whichever source arrived first.
// This exercises the actual HTTP decoder and skew watcher without sockets.
func TestPR80ForwardedClockSkewKeepsSourcesDistinct(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	previousNow := model.Now
	model.Now = func() time.Time { return now }
	t.Cleanup(func() { model.Now = previousNow })

	const token = "pr80-forwarder-fixture-token"
	fixtures := []struct {
		source, node, action string
		skew                 time.Duration
	}{
		{"idp.authentik", "idp-fixture", "auth.login", 11 * time.Minute},
		{"vpn.netbird", "vpn-fixture", "vpn.audit.peer.added", 45 * time.Minute},
	}
	for _, tc := range []struct {
		name, remoteAddr string
		separateRequests bool
	}{
		{"loopback_batch", "127.0.0.1:40000", false},
		{"loopback_separate_requests", "127.0.0.1:40001", true},
		{"reverse_proxy_batch", "192.0.2.200:40002", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := newSkewWatch(10 * time.Minute)
			var accepted []model.Event
			h := &listen.HTTPHandlers{
				Token: token,
				EmitBatch: func(_ context.Context, events []model.Event) error {
					for i := range events {
						// Same order as emitHTTPBatch in main.go. ASN lookup and
						// the durable sink do not participate in clock grouping.
						events[i].Attrs["transport"] = "http"
						watch.apply(&events[i], now)
					}
					accepted = append(accepted, events...)
					return nil
				},
			}
			mux := h.Mux()
			post := func(body []byte) {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, "/ingest/events", bytes.NewReader(body))
				req.RemoteAddr = tc.remoteAddr
				req.Header.Set("X-Argus-Token", token)
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusAccepted {
					t.Fatalf("ingest status=%d body=%s", rec.Code, rec.Body.String())
				}
			}
			var batch bytes.Buffer
			for _, fixture := range fixtures {
				event := model.Event{
					TS: model.FormatTS(now.Add(fixture.skew)), Source: fixture.source,
					Node: fixture.node, Action: fixture.action,
					Attrs: map[string]string{}, // Real VRL output has no peer or peer_cn.
				}
				if err := json.NewEncoder(&batch).Encode(event); err != nil {
					t.Fatal(err)
				}
				if tc.separateRequests {
					post(batch.Bytes())
					batch.Reset()
				}
			}
			if !tc.separateRequests {
				post(batch.Bytes())
			}
			if len(accepted) != len(fixtures) || watch.total.Load() != uint64(len(fixtures)) {
				t.Fatalf("want both events corrected, accepted=%d corrected=%d", len(accepted), watch.total.Load())
			}
			for i, event := range accepted {
				if event.Source != fixtures[i].source || event.Node != fixtures[i].node ||
					event.TS != model.FormatTS(now) || event.Attrs["ts_original"] != model.FormatTS(now.Add(fixtures[i].skew)) {
					t.Fatalf("input identity or timestamp correction changed: %+v", event)
				}
			}

			summaries := watch.flush(now.Add(time.Minute))
			if len(summaries) != len(fixtures) {
				t.Fatalf("distinct upstream sources behind %s collapsed: got %d summaries, want %d; summaries=%+v",
					tc.remoteAddr, len(summaries), len(fixtures), summaries)
			}
			bySource := make(map[string]model.Event, len(summaries))
			for _, summary := range summaries {
				if summary.Source != "argus.collector" || summary.Action != "collector.clock_skew" || summary.Attrs["transport"] != "internal" {
					t.Fatalf("not collector clock telemetry: %+v", summary)
				}
				bySource[summary.Attrs["source"]] = summary
			}
			for _, fixture := range fixtures {
				if summary, ok := bySource[fixture.source]; !ok || summary.Attrs["count"] != "1" || summary.Value != fixture.skew.Seconds() {
					t.Errorf("source %s must retain its own count=1 and skew=%.0f seconds; got %+v", fixture.source, fixture.skew.Seconds(), summary)
				}
			}
		})
	}
}
