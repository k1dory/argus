package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
)

type pr44WarningCounter struct{ count *atomic.Uint64 }

func (h pr44WarningCounter) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}
func (h pr44WarningCounter) Handle(_ context.Context, r slog.Record) error {
	if strings.HasPrefix(r.Message, "необъявленный формат:") {
		h.count.Add(1)
	}
	return nil
}
func (h pr44WarningCounter) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h pr44WarningCounter) WithGroup(string) slog.Handler      { return h }

// No parallel tests: isolate the package's global logger, metric and warning
// state, then restore them without copying sync.Map or atomic values.
func pr44IsolateWarnings(t *testing.T) *atomic.Uint64 {
	t.Helper()
	logger, total := slog.Default(), undeclaredFormatTotal.Load()
	saved := make(map[any]any)
	undeclaredWarned.Range(func(k, v any) bool {
		saved[k] = v
		undeclaredWarned.Delete(k)
		return true
	})
	undeclaredFormatTotal.Store(0)
	count := &atomic.Uint64{}
	slog.SetDefault(slog.New(pr44WarningCounter{count: count}))
	t.Cleanup(func() {
		undeclaredWarned.Range(func(k, _ any) bool {
			undeclaredWarned.Delete(k)
			return true
		})
		for k, v := range saved {
			undeclaredWarned.Store(k, v)
		}
		undeclaredFormatTotal.Store(total)
		slog.SetDefault(logger)
	})
	return count
}

func TestPR44UndeclaredWarningStillCountsAndThrottlesRealFallback(t *testing.T) {
	count := pr44IsolateWarnings(t)
	peer := listen.Peer{Addr: "192.0.2.20", Transport: "udp"}
	for i := 0; i < 2; i++ {
		e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, pr44CEF, peer)
		if !ok || e.SourceClass != "syslog" {
			t.Fatalf("undeclared CEF must use syslog: accepted=%v class=%q", ok, e.SourceClass)
		}
	}
	if count.Load() != 1 || undeclaredFormatTotal.Load() != 2 {
		t.Fatalf("want one warning and two fallback records, got warnings=%d records=%d", count.Load(), undeclaredFormatTotal.Load())
	}
}

// Existing CEF/LEEF compatibility tests accept these syslog envelopes when
// the format is declared. During migration the same envelopes without a
// declaration must all produce the promised warning and counter increment.
// ParseSyslog may consume "CEF:"/"LEEF:" as a TAG (or as part of HOSTNAME for
// PRI-only input); that must not hide the missing source configuration.
func TestPR44UndeclaredCEFLEEFWarnAcrossSyslogEnvelopes(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"cef", pr44CEF},
		{"leef", pr44LEEF + "^msg=blocked request"},
	} {
		for _, envelope := range []struct{ name, prefix string }{
			{"raw_control", ""},
			{"app_control", "<134>Nov  1 12:00:00 edge-fw exporter[42]: "},
			{"rfc5424_control", "<134>1 2026-11-01T12:00:00Z edge-fw exporter 42 - - "},
			{"rfc3164_without_app", "<134>Nov  1 12:00:00 edge-fw "},
			{"iso_without_app", "<134>2026-11-01T12:00:00Z edge-fw "},
			{"pri_only", "<134>"},
		} {
			t.Run(tc.name+"/"+envelope.name, func(t *testing.T) {
				count := pr44IsolateWarnings(t)
				line := envelope.prefix + tc.body
				e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{Addr: "192.0.2.20", Transport: "udp"})
				if !ok || e.SourceClass != "syslog" {
					t.Fatalf("undeclared vendor record must remain syslog: accepted=%v class=%q", ok, e.SourceClass)
				}
				if count.Load() != 1 || undeclaredFormatTotal.Load() != 1 {
					t.Errorf("syslog envelope hid the migration failure: warnings=%d undeclared=%d, want 1 each", count.Load(), undeclaredFormatTotal.Load())
				}
			})
		}
	}
}

// A one-minute throttle must not retain every UDP source IP forever. Use a
// small local batch and age its timestamps directly, without a wall-clock
// sleep, network traffic or a memory-exhaustion attempt.
func TestPR44UndeclaredWarningExpiresInactiveSenders(t *testing.T) {
	pr44IsolateWarnings(t)
	const senders = 256
	n := &normalize.Normalizer{}
	for i := 0; i < senders; i++ {
		peer := listen.Peer{Addr: fmt.Sprintf("198.18.0.%d", i), Transport: "udp"}
		if _, ok := parseSyslogLine(n, nil, pr44CEF, peer); !ok {
			t.Fatal("fixture was dropped")
		}
	}
	old := time.Now().Add(-24 * time.Hour)
	undeclaredWarned.Range(func(k, _ any) bool {
		undeclaredWarned.Store(k, old)
		return true
	})
	// Normal traffic after expiry must reclaim inactive senders, including
	// addresses that never send a second packet.
	for i := 0; i < senders; i++ {
		parseSyslogLine(n, nil, pr44CEF, listen.Peer{Addr: fmt.Sprintf("198.18.1.%d", i), Transport: "udp"})
	}
	stale := 0
	undeclaredWarned.Range(func(_, v any) bool {
		if v.(time.Time).Equal(old) {
			stale++
		}
		return true
	})
	if stale != 0 {
		t.Fatalf("warning throttle permanently retains %d inactive senders after another batch; source-IP churn grows collector memory", stale)
	}
}

// Native vendor formats remain supported without a format declaration.
// A marker inside an ordinary URL, account or filename is data, and must not
// advertise a migration failure after a vendor parser succeeds.
func TestPR44NativeVendorMarkersDoNotWarn(t *testing.T) {
	for _, marker := range []string{"plain", "CEF:", "LEEF:"} {
		for _, tc := range []struct{ name, line, source, action string }{
			{"qnap", `<30>Nov  1 12:00:00 nas-01 qulogd[1]: conn log: Users: alice, Source IP: 192.0.2.10, Computer name: client, Connection type: FTP, Accessed resources: Public/` + marker + `report.txt, Action: Delete`, "nas.qnap", "file.delete"},
			{"squid", `<134>Nov  1 12:00:00 proxy-01 squid[1]: 1757066138.684 215 192.0.2.10 TCP_DENIED/403 3985 GET http://example.test/` + marker + `manual alice HIER_NONE/- text/html`, "ngfw.squid", "session.deny"},
			{"jenkins", `<134>Nov  1 12:00:00 ci-01 jenkins[1]: job/` + marker + `deploy/configure Job configuration updated by user alice`, "jenkins.audit", "jenkins.configure"},
			{"mikrotik", `<134>Nov  1 12:00:00 router-01 system,info,account user ` + marker + `alice logged in from 192.0.2.10 via ssh`, "net.routeros", "auth.login"},
			{"vrp", `<189>Nov  1 2026 12:00:00 switch-01 %%01CLI/5/LOGOUT(s):CID=0x1;The user succeeded in logging out of VTY0. (UserType=SSH, UserName=` + marker + `alice, Ip=192.0.2.10)`, "net.vrp", "auth.logout"},
		} {
			t.Run(tc.name+"/"+marker, func(t *testing.T) {
				count := pr44IsolateWarnings(t)
				e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, tc.line, listen.Peer{Addr: "192.0.2.20", Transport: "udp"})
				if !ok || e.Source != tc.source || e.Action != tc.action {
					t.Fatalf("native vendor parser changed: accepted=%v source=%q action=%q", ok, e.Source, e.Action)
				}
				if count.Load() != 0 || undeclaredFormatTotal.Load() != 0 {
					t.Errorf("successfully parsed %s produced a false migration warning: warnings=%d undeclared=%d", tc.name, count.Load(), undeclaredFormatTotal.Load())
				}
			})
		}
	}
}
