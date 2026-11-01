package main

import "testing"

// RFC 3164 section 4.3.2 describes packets with a valid PRI but no timestamp.
// A CEF/LEEF header directly after PRI is still the application header, not a
// substring of request data. Spaces in that header must not hide its format.
// The same fixtures were accepted by the dispatcher at a808015.
// https://www.rfc-editor.org/rfc/rfc3164.html#section-4.3.2
func TestPR16Round5CEFLEEFWithPRIOnlyRetainSecurityFields(t *testing.T) {
	for _, format := range []struct{ name, payload, source, idKey string }{
		{
			"cef",
			"CEF:0|Check Point|VPN-1 & FireWall-1|R81|100|deny|8|src=203.0.113.50 dst=192.0.2.10 spt=51000 dpt=443 act=deny",
			"ngfw.checkpoint", "signature",
		},
		{
			"leef",
			"LEEF:2.0|UserGate|NGFW|7|100|^|src=203.0.113.50^dst=192.0.2.10^srcPort=51000^dstPort=443^action=deny^sev=8^msg=blocked request",
			"ngfw.usergate", "event_id",
		},
	} {
		for _, envelope := range []struct{ name, prefix string }{
			{"raw_control", ""},
			{"rfc3164_control", "<134>Nov  1 12:00:00 edge-fw exporter: "},
			{"pri_only", "<134>"},
		} {
			t.Run(format.name+"/"+envelope.name, func(t *testing.T) {
				events := wafHTTPBatch(t, "/ingest/syslog", envelope.prefix+format.payload, "192.0.2.20:31000")
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one vendor event", len(events))
				}
				e := events[0]
				if e.Source != format.source || e.SourceClass != "ngfw" || e.Attrs[format.idKey] != "100" {
					t.Errorf("PRI hid the CEF/LEEF header: source=%q class=%q id=%q", e.Source, e.SourceClass, e.Attrs[format.idKey])
				}
				if e.Action != "session.deny" || e.Outcome != "deny" || e.Severity != 8 || e.SrcIP != "203.0.113.50" || e.DstIP != "192.0.2.10" || e.SrcPort != 51000 || e.DstPort != 443 {
					t.Errorf("lost vendor security fields: action=%q outcome=%q severity=%d src=%q:%d dst=%q:%d", e.Action, e.Outcome, e.Severity, e.SrcIP, e.SrcPort, e.DstIP, e.DstPort)
				}
			})
		}
	}
}
