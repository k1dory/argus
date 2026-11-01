package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

// PR #78: exercise the real HTTP routes, normalizers and skew watcher together.
// Only the durable queue is replaced with an in-memory capture. The callback
// performs the transport assignment and skew check used by emitHTTPBatch;
// no sockets, background collector or ClickHouse instance are needed.
func pr78SkewHTTP(t *testing.T, watch *skewWatch, path, body, remote string) []model.Event {
	t.Helper()
	var captured []model.Event
	norm := &normalize.Normalizer{}
	h := &listen.HTTPHandlers{
		Token: "pr78-fixture-token",
		ParseLine: func(line string, peer listen.Peer) (model.Event, bool) {
			return parseSyslogLine(norm, nil, line, peer)
		},
		EmitBatch: func(_ context.Context, batch []model.Event) error {
			for i := range batch {
				if batch[i].Attrs == nil {
					batch[i].Attrs = map[string]string{}
				}
				batch[i].Attrs["transport"] = "http"
				watch.apply(&batch[i], model.Now())
			}
			captured = append(captured, batch...)
			return nil
		},
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.RemoteAddr = remote
	req.Header.Set("X-Argus-Token", "pr78-fixture-token")
	req.Header.Set("X-Forwarded-For", "198.51.100.250")
	rec := httptest.NewRecorder()
	h.Mux().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST %s: status=%d body=%s", path, rec.Code, rec.Body.String())
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ack); err != nil || ack.Accepted != len(captured) {
		t.Fatalf("ack=%s captured=%d error=%v", rec.Body.String(), len(captured), err)
	}
	return captured
}

func pr78SkewClock(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	previous := model.Now
	model.Now = func() time.Time { return now }
	t.Cleanup(func() { model.Now = previous })
	return now
}

// An authorized NDJSON sender may choose event contents, but may not cause the
// collector to issue trusted internal telemetry about another network peer.
// Syslog is the control: its parser already stamps the connection's address.
func TestPR78ClockSkewTelemetryUsesConnectionPeer(t *testing.T) {
	now := pr78SkewClock(t)
	future := now.Add(3 * time.Hour).Format(time.RFC3339)
	for _, tc := range []struct {
		name, path, body string
	}{
		{
			name: "ndjson forged peer",
			path: "/ingest/events",
			body: fmt.Sprintf(`{"ts":%q,"source":"nas.qnap","attrs":{"peer":"192.0.2.99","transport":"internal"}}`, future),
		},
		{
			name: "ndjson missing peer",
			path: "/ingest/events",
			body: fmt.Sprintf(`{"ts":%q,"source":"nas.qnap"}`, future),
		},
		{
			name: "syslog forged structured peer",
			path: "/ingest/syslog",
			body: fmt.Sprintf(`<86>1 %s sender audit - - [argus peer="192.0.2.99" transport="internal"] clock ahead`, future),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watch := newSkewWatch(10 * time.Minute)
			events := pr78SkewHTTP(t, watch, tc.path, tc.body, "192.0.2.10:31000")
			if len(events) != 1 {
				t.Fatalf("accepted %d events, want 1", len(events))
			}
			if events[0].TS != model.FormatTS(now) || events[0].Attrs["transport"] != "http" {
				t.Fatalf("ingress did not correct the future event: %+v", events[0])
			}
			summaries := watch.flush(now.Add(time.Minute))
			if len(summaries) != 1 {
				t.Fatalf("summaries=%+v, want one", summaries)
			}
			summary := summaries[0]
			if summary.Source != "argus.collector" || summary.Action != "collector.clock_skew" || summary.Attrs["transport"] != "internal" {
				t.Fatalf("not collector-owned telemetry: %+v", summary)
			}
			if got := summary.Attrs["peer"]; got != "192.0.2.10" {
				t.Errorf("trusted clock_skew attributed to %q; connection peer is 192.0.2.10", got)
			}
			if summary.Attrs["count"] != "1" || summary.Value != 10800 {
				t.Errorf("incorrect skew measurement: %+v", summary)
			}
		})
	}
}

// A spoofed peer must not merge one sender's measurements into a real syslog
// sender's bucket, increasing its count and maximum reported clock offset.
func TestPR78ClockSkewNDJSONCannotPoisonAnotherPeersSummary(t *testing.T) {
	now := pr78SkewClock(t)
	watch := newSkewWatch(10 * time.Minute)
	victim := fmt.Sprintf("<86>1 %s victim audit - - - clock ahead", now.Add(time.Hour).Format(time.RFC3339))
	pr78SkewHTTP(t, watch, "/ingest/syslog", victim, "192.0.2.99:32000")
	forged := fmt.Sprintf(`{"ts":%q,"source":"syslog.audit","attrs":{"peer":"192.0.2.99"}}`, now.Add(3*time.Hour).Format(time.RFC3339))
	pr78SkewHTTP(t, watch, "/ingest/events", forged, "192.0.2.10:31000")

	summaries := watch.flush(now.Add(time.Minute))
	if len(summaries) != 2 {
		t.Errorf("two connection peers require separate summaries, got %+v", summaries)
	}
	byPeer := map[string]model.Event{}
	for _, summary := range summaries {
		byPeer[summary.Attrs["peer"]] = summary
	}
	if got := byPeer["192.0.2.99"]; got.Attrs["count"] != "1" || got.Value != 3600 {
		t.Errorf("other sender contaminated the victim's skew measurement: %+v", got)
	}
	if got := byPeer["192.0.2.10"]; got.Attrs["count"] != "1" || got.Value != 10800 {
		t.Errorf("missing measurement for the actual NDJSON sender: %+v", got)
	}
}
