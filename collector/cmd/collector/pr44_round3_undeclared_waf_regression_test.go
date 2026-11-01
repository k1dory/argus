package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// These tests are deliberately sequential: the warning logger and limiter are
// package globals. Restore all state, including the counters added in round 3.
func pr44Round3CaptureWarnings(t *testing.T) *bytes.Buffer {
	t.Helper()
	logger := slog.Default()
	total, stores, seen := undeclaredFormatTotal.Load(), undeclaredStores.Load(), undeclaredSeen.Load()
	overflowAt := undeclaredOverflowAt
	saved := make(map[any]any)
	undeclaredWarned.Range(func(k, v any) bool {
		saved[k] = v
		undeclaredWarned.Delete(k)
		return true
	})
	undeclaredFormatTotal.Store(0)
	undeclaredStores.Store(0)
	undeclaredSeen.Store(0)
	undeclaredOverflowAt = time.Time{}
	logs := &bytes.Buffer{}
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() {
		undeclaredWarned.Range(func(k, _ any) bool {
			undeclaredWarned.Delete(k)
			return true
		})
		for k, v := range saved {
			undeclaredWarned.Store(k, v)
		}
		undeclaredFormatTotal.Store(total)
		undeclaredStores.Store(stores)
		undeclaredSeen.Store(seen)
		undeclaredOverflowAt = overflowAt
		slog.SetDefault(logger)
	})
	return logs
}

// The same decoded Caddy message must be quarantined before native vendor
// parsers whether the JSON spells the marker literally or with a JSON escape.
// /credentials is ordinary HTTP request data but also matches ParseJenkins.
func TestPR44Round3EscapedWAFPayloadCannotFallThroughToJenkins(t *testing.T) {
	for _, marker := range []string{"Coraza", "ModSecurity"} {
		literal := strings.Replace(pr44Caddy, "Coraza:", marker+":", 1)
		literal = strings.Replace(literal, "/account", "/credentials", 1)
		for _, encoding := range []struct{ name, body string }{
			{"literal_control", literal},
			{"escaped_space", strings.Replace(literal, marker+": ", marker+`:\u0020`, 1)},
		} {
			if !parse.IsWAFErrorLine(encoding.body) {
				t.Fatalf("invalid %s/%s WAF fixture", marker, encoding.name)
			}
			if marker == "Coraza" {
				if w, ok := parse.ParseCorazaLine(encoding.body); !ok || !w.Final || !w.Blocked {
					t.Fatalf("declared Coraza parser must recognize this same JSON: accepted=%v waf=%+v", ok, w)
				}
			}
			for _, envelope := range []struct{ name, prefix string }{
				{"raw_control", ""},
				{"rfc3164", "<134>Nov  1 12:00:00 waf-01 caddy[42]: "},
				{"rfc5424", "<134>1 2026-11-01T12:00:00Z waf-01 caddy 42 - - "},
			} {
				for _, format := range []string{"", parse.FormatCEF, parse.FormatLEEF} {
					t.Run(marker+"/"+encoding.name+"/"+envelope.name+"/format="+format, func(t *testing.T) {
						logs := pr44Round3CaptureWarnings(t)
						line := envelope.prefix + encoding.body
						events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", format)
						if len(events) != 1 {
							t.Fatalf("accepted=%d, want one searchable WAF message", len(events))
						}
						e := events[0]
						if e.SourceClass != "syslog" || !strings.HasPrefix(e.Action, "syslog.") || e.Outcome != "unknown" || e.Attrs["waf_unparsed"] != "1" || e.Raw != line {
							t.Errorf("encoded WAF request selected a vendor parser or lost quarantine: class=%q action=%q outcome=%q waf_unparsed=%q raw_preserved=%v", e.SourceClass, e.Action, e.Outcome, e.Attrs["waf_unparsed"], e.Raw == line)
						}
						wantWarnings := uint64(0)
						if format == "" {
							wantWarnings = 1
						}
						warnings := uint64(strings.Count(logs.String(), `"msg":"необъявленный формат:`))
						if warnings != wantWarnings || undeclaredFormatTotal.Load() != wantWarnings {
							t.Errorf("lost migration warning: warnings=%d metric=%d, want %d each", warnings, undeclaredFormatTotal.Load(), wantWarnings)
						}
					})
				}
			}
		}
	}
}

// Verify the round-3 contract itself, not the older test's looser 4096 limit.
// A small in-process batch exercises the cap and the summary without sockets,
// sleeps, an exhaustion attempt or any change to the production clock.
func TestPR44Round3WarningCapAndOverflowSummary(t *testing.T) {
	logs := pr44Round3CaptureWarnings(t)
	const limit, senders = 1024, 1088
	started := time.Now()
	n := &normalize.Normalizer{}
	for i := 0; i < senders; i++ {
		peer := listen.Peer{Addr: fmt.Sprintf("198.18.%d.%d", i/256, i%256), Transport: "udp"}
		if e, ok := parseSyslogLine(n, nil, pr44CEF, peer); !ok || e.SourceClass != "syslog" {
			t.Fatalf("sender %d: undeclared event was lost or reclassified", i)
		}
	}
	entries := 0
	undeclaredWarned.Range(func(_, _ any) bool { entries++; return true })
	if entries > limit {
		t.Fatalf("warning table holds %d peers, maximum is %d", entries, limit)
	}
	if undeclaredFormatTotal.Load() != senders {
		t.Fatalf("metric=%d, want all %d records including overflow", undeclaredFormatTotal.Load(), senders)
	}
	if time.Since(started) >= time.Minute {
		t.Skip("fixture crossed the TTL; per-minute warning counts cannot be asserted")
	}
	individual := strings.Count(logs.String(), `"msg":"необъявленный формат:`)
	summaries := strings.Count(logs.String(), `"msg":"необъявленный формат у многих отправителей:`)
	if individual != limit || summaries != 1 {
		t.Errorf("individual warnings=%d summaries=%d, want %d and 1", individual, summaries, limit)
	}
}
