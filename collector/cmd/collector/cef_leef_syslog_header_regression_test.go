package main

import "testing"

// CEF and LEEF can immediately follow the syslog hostname, without an app tag:
// https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
// https://www.ibm.com/docs/en/gdp/12.x?topic=integration-leef-mapping
// RFC 5424 also permits a UTF-8 BOM at the beginning of MSG (section 6.4).
// Exercise ingestion: testing ParseCEF/ParseLEEF alone misses dispatch failures.
func TestPR16Round3CEFLEEFHeadersSurviveSyslogEnvelopes(t *testing.T) {
	for _, format := range []struct {
		name, payload, source, vendor, product, idKey string
	}{
		{
			name: "checkpoint_cef", source: "ngfw.checkpoint", vendor: "Check Point", product: "VPN-1 & FireWall-1", idKey: "signature",
			payload: `CEF:0|Check Point|VPN-1 & FireWall-1|R81|100|deny|8|src=203.0.113.50 dst=192.0.2.10 spt=51000 dpt=443 act=deny`,
		},
		{
			name: "fortigate_cef", source: "ngfw.fortigate", vendor: "Fortinet", product: "FortiGate", idKey: "signature",
			payload: `CEF:0|Fortinet|FortiGate|7.2|100|deny|8|src=203.0.113.50 dst=192.0.2.10 spt=51000 dpt=443 act=deny`,
		},
		{
			name: "usergate_leef1", source: "ngfw.usergate", vendor: "UserGate", product: "NGFW", idKey: "event_id",
			payload: "LEEF:1.0|UserGate|NGFW|7|100|src=203.0.113.50\tdst=192.0.2.10\tsrcPort=51000\tdstPort=443\taction=deny\tsev=8",
		},
		{
			name: "ideco_leef2", source: "ngfw.ideco", vendor: "Ideco", product: "UTM", idKey: "event_id",
			payload: `LEEF:2.0|Ideco|UTM|16|100|^|src=203.0.113.50^dst=192.0.2.10^srcPort=51000^dstPort=443^action=deny^sev=8`,
		},
	} {
		for _, envelope := range []struct{ name, prefix string }{
			{"raw_control", ""},
			{"rfc3164_app_control", "<134>Oct 29 17:39:38 edge-fw exporter[42]: "},
			{"rfc5424_control", "<134>1 2026-10-29T17:39:38Z edge-fw exporter 42 - - "},
			{"rfc3164_without_app", "<134>Oct 29 17:39:38 edge-fw "},
			{"rsyslog_iso_without_app", "<134>2026-10-29T17:39:38Z edge-fw "},
			{"file_without_pri", "Oct 29 17:39:38 edge-fw "},
			{"rfc5424_utf8_bom", "<134>1 2026-10-29T17:39:38Z edge-fw exporter 42 - - \ufeff"},
		} {
			t.Run(format.name+"/"+envelope.name, func(t *testing.T) {
				line := envelope.prefix + format.payload
				events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", formatOf(line))
				if len(events) != 1 {
					t.Fatalf("accepted %d events, want one vendor event", len(events))
				}
				e := events[0]
				if e.Source != format.source || e.SourceClass != "ngfw" || e.Vendor != format.vendor || e.Product != format.product {
					t.Errorf("syslog envelope hid the format header: source=%q class=%q vendor=%q product=%q", e.Source, e.SourceClass, e.Vendor, e.Product)
				}
				if e.SrcIP != "203.0.113.50" || e.DstIP != "192.0.2.10" || e.SrcPort != 51000 || e.DstPort != 443 || e.Action != "session.deny" || e.Outcome != "deny" || e.Severity != 8 || e.Attrs[format.idKey] != "100" {
					t.Errorf("lost vendor security fields: src=%q:%d dst=%q:%d action=%q outcome=%q severity=%d id=%q", e.SrcIP, e.SrcPort, e.DstIP, e.DstPort, e.Action, e.Outcome, e.Severity, e.Attrs[format.idKey])
				}
			})
		}
	}
}
