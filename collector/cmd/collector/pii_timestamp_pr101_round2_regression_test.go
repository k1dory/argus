package main

import (
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Общая проверка ПДн не должна превращать миллисекундное время CEF/LEEF
// в телефон: в 1780000000000 phoneRe находит подстроку 80000000000.
// До общей проверки FromCEF/FromLEEF не считали поле времени ПДн.
// Ложный pii=1 меняет профиль analyst.Route для всего инцидента.
func TestPR101Round2StructuredTimestampsAreNotPII(t *testing.T) {
	for _, format := range []struct {
		name, format, header, timeKey, separator, source string
	}{
		{
			name: "cef", format: parse.FormatCEF,
			header:  "CEF:0|Check Point|Firewall|1|100|deny|5|",
			timeKey: "rt", separator: " ", source: "ngfw.checkpoint",
		},
		{
			name: "leef", format: parse.FormatLEEF,
			header:  "LEEF:1.0|UserGate|NGFW|7|100|",
			timeKey: "devTime", separator: "\t", source: "ngfw.usergate",
		},
	} {
		for _, envelope := range []struct{ name, prefix string }{
			{"raw", ""},
			{"rfc3164", "<134>Nov  1 12:00:00 edge-fw exporter[12]: "},
			{"rfc5424", "<134>1 2026-11-01T12:00:00Z edge-fw exporter 12 - - "},
		} {
			for _, tc := range []struct {
				name, timestamp, message string
				pii                      uint8
			}{
				{"control_timestamp", "1757066138000", "connection denied", 0},
				{"timestamp_containing_phone_pattern", "1780000000000", "connection denied", 0},
				{"real_email", "1780000000000", "alice@example.test", 1},
				{"real_phone", "1780000000000", "+1 202 555 0100", 1},
			} {
				t.Run(format.name+"/"+envelope.name+"/"+tc.name, func(t *testing.T) {
					line := envelope.prefix + format.header + format.timeKey + "=" + tc.timestamp +
						format.separator + "src=192.0.2.10" + format.separator + "msg=" + tc.message
					e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, listen.Peer{
						Addr: "192.0.2.40", Transport: "udp", Format: format.format,
					})
					if !ok || e.Source != format.source || e.SrcIP != "192.0.2.10" {
						t.Fatalf("vendor event was not preserved: ok=%v source=%q src=%q", ok, e.Source, e.SrcIP)
					}
					if e.PII != tc.pii {
						t.Errorf("%s=%s msg=%q: pii=%d, want %d; an epoch timestamp is not a phone number",
							format.timeKey, tc.timestamp, tc.message, e.PII, tc.pii)
					}
				})
			}
		}
	}
}
