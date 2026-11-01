package main

import (
	"encoding/json"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// The first space in a raw record can be inside a request-derived msg value.
// "Forwarded:" there is data, not a syslog TAG. Adding a synthetic PRI must not
// strip the real record and promote the following client text to a new record.
// LEEF 1 uses tabs, so the nested LEEF 2 fixture contains no outer delimiters.
// Pipes inside a CEF extension value do not require escaping (CEF standard,
// "Character Escaping"); the nested CEF header contains no equals signs:
// https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/pdfdoc/cef-implementation-standard/cef-implementation-standard.pdf
// https://ibmsecuritydocs.github.io/qradar_appfw_v2/docs/tutorials/generating_LEEF_events.html
func TestPR44Round3RawRequestDataCannotReplaceOuterRecord(t *testing.T) {
	for _, format := range []struct {
		name, header, suffix, source, idKey, nested string
	}{
		{
			name: "cef", header: "CEF:0|Fortinet|FortiGate|7|100|deny|8|",
			suffix: " src=203.0.113.50 dst=192.0.2.10",
			source: "ngfw.fortigate", idKey: "signature",
			nested: "CEF:0|Fortinet|FortiGate|7|999|allow|1|",
		},
		{
			name: "leef", header: "LEEF:1.0|UserGate|NGFW|7|100|",
			suffix: "\tsrc=203.0.113.50\tdst=192.0.2.10\taction=deny\tsev=8",
			source: "ngfw.usergate", idKey: "event_id",
			nested: "LEEF:2.0|UserGate|NGFW|7|999|^|src=198.51.100.99^dst=192.0.2.99^action=allow^sev=1^unused=fixture",
		},
	} {
		marker := "CEF:"
		if format.name == "leef" {
			marker = "LEEF:"
		}
		for _, request := range []struct{ name, value string }{
			{"ordinary_control", "ordinary-value"},
			{"incomplete_marker", "Forwarded: " + marker + "client-data"},
			{"complete_nested_record", "Forwarded: " + format.nested},
		} {
			body := format.header + "msg=prefix " + request.value + format.suffix
			// Establish that these are valid outer records with an intact msg,
			// rather than fixtures that already overwrite extension fields.
			n := &normalize.Normalizer{}
			var outer model.Event
			var msg string
			if format.name == "cef" {
				c, ok := parse.ParseCEF(body)
				if !ok {
					t.Fatal("invalid outer CEF fixture")
				}
				outer, msg = n.FromCEF(c, parse.Syslog{}, body), c.Ext["msg"]
			} else {
				l, ok := parse.ParseLEEF(body)
				if !ok {
					t.Fatal("invalid outer LEEF fixture")
				}
				outer, msg = n.FromLEEF(l, parse.Syslog{}, body), l.Ext["msg"]
			}
			if msg != "prefix "+request.value || outer.Source != format.source || outer.Action != "session.deny" || outer.Outcome != "deny" || outer.Severity != 8 || outer.Attrs[format.idKey] != "100" || outer.SrcIP != "203.0.113.50" || outer.DstIP != "192.0.2.10" {
				t.Fatalf("invalid %s/%s fixture: msg=%q event=%+v", format.name, request.name, msg, outer)
			}
			for _, envelope := range []struct{ name, prefix string }{
				{"raw", ""},
				{"pri_only", "<134>"},
				{"rfc3164_app_control", "<134>Nov  1 12:00:00 edge-fw exporter[42]: "},
				{"rfc3164_no_app_control", "<134>Nov  1 12:00:00 edge-fw "},
				{"no_pri_app_control", "Nov  1 12:00:00 edge-fw exporter[42]: "},
				{"no_pri_no_app_control", "Nov  1 12:00:00 edge-fw "},
				{"rfc5424_bom_control", "<134>1 2026-11-01T12:00:00Z edge-fw exporter 42 - - \ufeff"},
			} {
				t.Run(format.name+"/"+request.name+"/"+envelope.name, func(t *testing.T) {
					line := envelope.prefix + body
					events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", format.name)
					if outsideRecordForms(t, envelope.name, events) {
						return
					}
					if len(events) != 1 {
						t.Fatalf("accepted=%d, want one original vendor event", len(events))
					}
					e := events[0]
					if e.Source != format.source || e.SourceClass != "ngfw" || e.Action != "session.deny" || e.Outcome != "deny" || e.Severity != 8 || e.Attrs[format.idKey] != "100" || e.SrcIP != "203.0.113.50" || e.DstIP != "192.0.2.10" {
						t.Errorf("request text replaced the outer record: source=%q class=%q action=%q outcome=%q severity=%d id=%q src=%q dst=%q", e.Source, e.SourceClass, e.Action, e.Outcome, e.Severity, e.Attrs[format.idKey], e.SrcIP, e.DstIP)
					}
					if e.Raw != line {
						t.Error("raw evidence changed")
					}
				})
			}
		}
	}
}

// A raw JSON field is not a syslog HOSTNAME. A marker in its first token must
// not pass the special handling for PRI-only CEF/LEEF records.
func TestPR44Round3RawJSONFieldCannotBecomeRecordHeader(t *testing.T) {
	for _, format := range []struct{ name, record string }{
		{"cef", pr44CEF + " unused=fixture"},
		{"leef", pr44LEEF + "^unused=blocked request"},
	} {
		t.Run(format.name, func(t *testing.T) {
			body, err := json.Marshal(struct {
				Request string `json:"request"`
			}{Request: format.record})
			if err != nil {
				t.Fatal(err)
			}
			line := string(body)
			events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", format.name)
			if len(events) != 1 {
				t.Fatalf("accepted=%d, want one searchable JSON message", len(events))
			}
			e := events[0]
			if e.SourceClass != "syslog" || e.Outcome != "unknown" || e.Attrs["signature"] != "" || e.Attrs["event_id"] != "" || e.Raw != line {
				t.Errorf("raw JSON field became a vendor record: class=%q action=%q outcome=%q signature=%q event_id=%q", e.SourceClass, e.Action, e.Outcome, e.Attrs["signature"], e.Attrs["event_id"])
			}
		})
	}
}
