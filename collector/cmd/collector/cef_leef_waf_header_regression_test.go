package main

import (
	"testing"
)

// A syslog TAG/APP-NAME or HOSTNAME is not the application payload. In
// particular, "Coraza: " in the envelope must not veto a genuine CEF/LEEF
// header in MSG. The extension's WAF marker is request/log text, not a second
// event; a Warning there must not make the collector drop the vendor event.
func TestPR16Round4CEFLEEFIgnoreWAFMarkersInSyslogHeader(t *testing.T) {
	for _, format := range []struct{ name, payload, suffix, source, idKey string }{
		{
			name:    "cef",
			payload: `CEF:0|Check Point|VPN-1 & FireWall-1|R81|100|deny|8|src=203.0.113.50 dst=192.0.2.10 spt=51000 dpt=443 act=deny`,
			suffix:  " msg=ModSecurity: Warning.", source: "ngfw.checkpoint", idKey: "signature",
		},
		{
			name:    "leef",
			payload: `LEEF:2.0|UserGate|NGFW|7|100|^|src=203.0.113.50^dst=192.0.2.10^srcPort=51000^dstPort=443^action=deny^sev=8`,
			suffix:  "^msg=ModSecurity: Warning.", source: "ngfw.usergate", idKey: "event_id",
		},
	} {
		for _, envelope := range []struct{ name, prefix string }{
			{"raw_control", ""},
			{"ordinary_tag_control", "<134>Nov  1 12:00:00 edge-fw exporter: "},
			{"rfc3164_coraza_tag", "<134>Nov  1 12:00:00 edge-fw Coraza: "},
			{"rfc3164_modsecurity_tag", "<134>Nov  1 12:00:00 edge-fw ModSecurity: "},
			{"rfc5424_coraza_hostname", "<134>1 2026-11-01T12:00:00Z Coraza: exporter 42 - - "},
			{"rfc5424_coraza_app", "<134>1 2026-11-01T12:00:00Z edge-fw Coraza: 42 - - "},
			{"no_pri_coraza_tag", "Nov  1 12:00:00 edge-fw Coraza: "},
		} {
			for _, extension := range []struct{ name, value string }{
				{"ordinary_extension", ""},
				{"waf_text_in_extension", format.suffix},
			} {
				t.Run(format.name+"/"+envelope.name+"/"+extension.name, func(t *testing.T) {
					line := envelope.prefix + format.payload + extension.value
					events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", formatOf(line))
					if outsideRecordForms(t, envelope.name, events) {
						return
					}
					if len(events) != 1 {
						t.Fatalf("vendor event discarded as an intermediate WAF warning: accepted=%d, want=1", len(events))
					}
					e := events[0]
					if e.Source != format.source || e.SourceClass != "ngfw" || e.Attrs[format.idKey] != "100" {
						t.Errorf("syslog header changed the application parser: source=%q class=%q id=%q", e.Source, e.SourceClass, e.Attrs[format.idKey])
					}
					if e.Action != "session.deny" || e.Outcome != "deny" || e.Severity != 8 || e.SrcIP != "203.0.113.50" || e.DstIP != "192.0.2.10" || e.SrcPort != 51000 || e.DstPort != 443 {
						t.Errorf("lost vendor security fields: action=%q outcome=%q severity=%d src=%q:%d dst=%q:%d",
							e.Action, e.Outcome, e.Severity, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
					}
				})
			}
		}
	}
}
