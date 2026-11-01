package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// A CEF/LEEF record can immediately follow HOSTNAME, with no separate app TAG.
// ParseSyslog consumes CEF:/LEEF: as that TAG (or part of HOSTNAME for PRI-only
// input). Marker ordering must still refer to the complete application record,
// not to the suffix left in sl.Message. The msg extension is ordinary data.
func TestPR44ReReviewVendorMarkerOrderSurvivesSyslogParsing(t *testing.T) {
	for _, record := range []struct{ format, body, suffix, source, idKey string }{
		{parse.FormatCEF, pr44CEF, " msg=", "ngfw.checkpoint", "signature"},
		{parse.FormatLEEF, pr44LEEF + "^sev=8", "^msg=", "ngfw.usergate", "event_id"},
	} {
		for _, data := range []struct{ name, value string }{
			{"control", "blocked request"},
			{"request_marker", "request header: ModSecurity: Warning."},
		} {
			for _, envelope := range []struct{ name, prefix string }{
				{"raw_control", ""},
				{"rfc3164_app_control", "<134>Nov  1 12:00:00 edge-fw exporter[42]: "},
				{"rfc5424_control", "<134>1 2026-11-01T12:00:00Z edge-fw exporter 42 - - "},
				{"rfc3164_without_app", "<134>Nov  1 12:00:00 edge-fw "},
				{"iso_without_app", "<134>2026-11-01T12:00:00Z edge-fw "},
				{"pri_only", "<134>"},
			} {
				t.Run(record.format+"/"+data.name+"/"+envelope.name, func(t *testing.T) {
					line := envelope.prefix + record.body + record.suffix + data.value
					events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", record.format)
					if len(events) != 1 {
						t.Fatalf("accepted=%d, want one vendor event", len(events))
					}
					e := events[0]
					if e.Source != record.source || e.SourceClass != "ngfw" || e.Action != "session.deny" || e.Outcome != "deny" || e.Attrs[record.idKey] != "100" || e.Attrs["waf_unparsed"] != "" {
						t.Errorf("syslog parsing changed marker order: source=%q class=%q action=%q outcome=%q id=%q waf_unparsed=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.Attrs[record.idKey], e.Attrs["waf_unparsed"])
					}
					if e.SrcIP != "203.0.113.50" || e.DstIP != "192.0.2.10" || e.Severity != 8 || e.Raw != line {
						t.Errorf("lost vendor security fields/evidence: src=%q dst=%q severity=%d raw_preserved=%v", e.SrcIP, e.DstIP, e.Severity, e.Raw == line)
					}
				})
			}
		}
	}
}

// The inverse boundary matters too: when the real ModSecurity marker becomes
// the RFC 3164 TAG, a CEF/LEEF record inside its unescaped msg must not become
// the outer record. A genuine CEF/LEEF body after a ModSecurity TAG remains
// covered by TestPR16Round4CEFLEEFIgnoreWAFMarkersInSyslogHeader.
func TestPR44ReReviewModSecurityTagCannotPromoteEmbeddedRecord(t *testing.T) {
	for _, record := range []struct{ format, body string }{
		{parse.FormatCEF, pr44CEF + " unused=fixture"},
		{parse.FormatLEEF, pr44LEEF + "^unused=fixture"},
	} {
		message := fmt.Sprintf(`Access denied with code 403 (phase 2). [file "/etc/modsecurity/local.conf"] [id "1001"] [msg "Header %s"] [severity "2"] [hostname "shop.example"] [uri "/account"] [unique_id "pr44-rereview-modsec"]`, record.body)
		for _, envelope := range []struct{ name, prefix string }{
			{"raw_control", "ModSecurity: "},
			{"app_control", "<134>Nov  1 12:00:00 waf-01 nginx[42]: ModSecurity: "},
			{"rfc3164_modsecurity_tag", "<134>Nov  1 12:00:00 waf-01 ModSecurity: "},
			{"iso_modsecurity_tag", "<134>2026-11-01T12:00:00Z waf-01 ModSecurity: "},
		} {
			t.Run(record.format+"/"+envelope.name, func(t *testing.T) {
				line := envelope.prefix + message
				events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", record.format)
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one searchable ModSecurity record", len(events))
				}
				e := events[0]
				if e.SourceClass != "syslog" || !strings.HasPrefix(e.Action, "syslog.") || e.Outcome != "unknown" || e.Attrs["waf_unparsed"] != "1" || e.Attrs["signature"] != "" || e.Attrs["event_id"] != "" {
					t.Errorf("embedded record became authoritative after stripping the TAG: class=%q action=%q outcome=%q waf_unparsed=%q signature=%q event_id=%q", e.SourceClass, e.Action, e.Outcome, e.Attrs["waf_unparsed"], e.Attrs["signature"], e.Attrs["event_id"])
				}
				if e.Raw != line {
					t.Error("raw ModSecurity evidence changed")
				}
			})
		}
	}
}
