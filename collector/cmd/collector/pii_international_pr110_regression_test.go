package main

import (
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Проверяем реальный путь приёма: потеря PII в HasPII не компенсируется
// ни детектором полей CEF/LEEF, ни общей проверкой payload/APP-NAME.
func TestPR110IngestPreservesInternationalPhonePII(t *testing.T) {
	const phone = "+4917612345678"
	for _, tc := range []struct {
		name, format, payload, source string
	}{
		{"syslog", "", "callback=" + phone + " rt=1780000000000", "syslog.exporter"},
		{"cef_message", parse.FormatCEF, "CEF:0|Check Point|Firewall|1|100|deny|5|rt=1780000000000 msg=callback=" + phone, "ngfw.checkpoint"},
		{"cef_phone_field", parse.FormatCEF, "CEF:0|Check Point|Firewall|1|100|deny|5|rt=1780000000000 msisdn=" + phone, "ngfw.checkpoint"},
		{"leef_message", parse.FormatLEEF, "LEEF:1.0|UserGate|NGFW|7|100|devTime=1780000000000\tmsg=callback=" + phone, "ngfw.usergate"},
		{"leef_phone_field", parse.FormatLEEF, "LEEF:1.0|UserGate|NGFW|7|100|devTime=1780000000000\tmsisdn=" + phone, "ngfw.usergate"},
	} {
		for _, envelope := range []struct{ name, prefix string }{
			{"raw", ""},
			{"rfc3164", "<134>Nov  1 12:00:00 edge-fw exporter[12]: "},
			{"rfc5424", "<134>1 2026-11-01T12:00:00Z edge-fw exporter 12 - - "},
		} {
			t.Run(tc.name+"/"+envelope.name, func(t *testing.T) {
				line := envelope.prefix + tc.payload
				e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{
					Addr: "192.0.2.40", Transport: "udp", Format: tc.format,
				})
				wantSource := tc.source
				if tc.name == "syslog" && envelope.name == "raw" {
					wantSource = "syslog.generic"
				}
				if !ok || e.Source != wantSource {
					t.Fatalf("fixture was not dispatched as expected: ok=%v source=%q, want %q", ok, e.Source, wantSource)
				}
				if !strings.Contains(e.Raw, phone) {
					t.Fatal("fixture lost its phone before the PII assertion")
				}
				if e.PII != 1 {
					t.Errorf("phone %q remains in the event but pii=%d; want pii=1 to keep its incident local", phone, e.PII)
				}
			})
		}
	}

	t.Run("rfc5424_app_name", func(t *testing.T) {
		line := "<134>1 2026-11-01T12:00:00Z edge-fw " + phone + " 12 - - connection denied"
		e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{Addr: "192.0.2.40", Transport: "udp"})
		if !ok || e.Source != "syslog.generic" || e.Attrs["tag"] != phone {
			t.Fatalf("rejected APP-NAME was not preserved: ok=%v source=%q tag=%q", ok, e.Source, e.Attrs["tag"])
		}
		if e.PII != 1 {
			t.Errorf("phone in APP-NAME/attrs.tag has pii=%d, want 1", e.PII)
		}
	})
}
