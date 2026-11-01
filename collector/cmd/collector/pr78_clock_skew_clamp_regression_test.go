package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// SetTS/Ensure run before the new guard. A timestamp beyond MaxFuture is
// therefore replaced with now before apply can preserve it or count the skew.
// Test both real ingress paths, including either side of the legacy 24h bound.
func TestPR78ClockSkewBeyondLegacyClampIsStillReported(t *testing.T) {
	now := pr78SkewClock(t)
	for _, ahead := range []time.Duration{23 * time.Hour, 24 * time.Hour, 24*time.Hour + time.Second, 48 * time.Hour} {
		for _, path := range []string{"/ingest/events", "/ingest/syslog"} {
			t.Run(fmt.Sprintf("%s/%s", path, ahead), func(t *testing.T) {
				t.Setenv("COLLECTOR_CLOCK_SKEW_MAX", "5m")
				watch := newSkewWatch(clockSkewMax())
				original := now.Add(ahead)
				stamp := original.Format(time.RFC3339)
				body := fmt.Sprintf(`{"ts":%q,"source":"syslog.audit","attrs":{"peer":"192.0.2.10","ts_original":"forged"}}`, stamp)
				if path == "/ingest/syslog" {
					body = fmt.Sprintf("<86>1 %s sender audit - - - clock ahead", stamp)
				}
				events := pr78SkewHTTP(t, watch, path, body, "192.0.2.10:31000")
				if len(events) != 1 {
					t.Fatalf("accepted %d events, want 1", len(events))
				}
				event := events[0]
				if event.TS != model.FormatTS(now) {
					t.Errorf("ts=%q, want receipt time %q", event.TS, model.FormatTS(now))
				}
				if saved, ok := model.ParseTS(event.Attrs["ts_original"]); !ok || !saved.Equal(original) {
					t.Errorf("lost original future timestamp %s: ts_original=%q ts_raw=%q", stamp, event.Attrs["ts_original"], event.Attrs["ts_raw"])
				}
				if got := watch.total.Load(); got != 1 {
					t.Errorf("clock_skew_total=%d, want 1 for a timestamp %s ahead", got, ahead)
				}
				summaries := watch.flush(now.Add(time.Minute))
				if len(summaries) != 1 {
					t.Fatalf("clock_skew summaries=%+v, want one for a timestamp %s ahead", summaries, ahead)
				}
				if summary := summaries[0]; summary.Attrs["count"] != "1" || summary.Attrs["threshold_sec"] != "300" || summary.Value != ahead.Seconds() {
					t.Errorf("incorrect skew measurement: %+v", summary)
				}
			})
		}
	}
}

// Preserve the trust boundary when fixing the legacy-clamp gap: ts_raw is also
// accepted from an NDJSON body, so its mere presence is not proof of a clamp.
// A previous skew from the same sender must not shift later events backwards.
func TestPR78ClockSkewIgnoresSpoofedTimestampMetadata(t *testing.T) {
	now := pr78SkewClock(t)
	watch := newSkewWatch(10 * time.Minute)
	seed := fmt.Sprintf(`{"ts":%q,"source":"syslog.audit","attrs":{"peer":"192.0.2.10"}}`, now.Add(3*time.Hour).Format(time.RFC3339))
	pr78SkewHTTP(t, watch, "/ingest/events", seed, "192.0.2.10:31000")
	watch.flush(now)

	for _, offset := range []time.Duration{-time.Hour, 0, 5 * time.Minute} {
		t.Run(offset.String(), func(t *testing.T) {
			stamp := now.Add(offset)
			body := fmt.Sprintf(`{"ts":%q,"source":"syslog.audit","attrs":{"peer":"192.0.2.10","ts_original":%q,"ts_raw":%q}}`,
				stamp.Format(time.RFC3339), now.Add(-3*time.Hour).Format(time.RFC3339), now.Add(48*time.Hour).Format(time.RFC3339))
			events := pr78SkewHTTP(t, watch, "/ingest/events", body, "192.0.2.10:31000")
			if len(events) != 1 {
				t.Fatalf("accepted %d events, want 1", len(events))
			}
			if got := events[0].TS; got != model.FormatTS(stamp) {
				t.Errorf("sender metadata or prior skew changed ts: got %q, want %q", got, model.FormatTS(stamp))
			}
			if _, exists := events[0].Attrs["ts_original"]; exists {
				t.Errorf("sender-provided ts_original survived ingestion: %+v", events[0].Attrs)
			}
		})
	}
	if got := watch.total.Load(); got != 1 {
		t.Errorf("sender-provided ts_raw forged clock_skew telemetry: total=%d, want only the seed event", got)
	}
	if summaries := watch.flush(now.Add(time.Minute)); len(summaries) != 0 {
		t.Errorf("in-range events generated clock_skew telemetry: %+v", summaries)
	}
}
