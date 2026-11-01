package main

import (
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// A request URL in a genuine, undeclared CEF/LEEF record must not select the
// Jenkins parser. During migration these records must remain syslog and must
// count toward the missing-format warning, regardless of the requested URL.
// TestPR44NativeVendorMarkersDoNotWarn covers the inverse boundary: markers
// inside genuine native vendor data must not cause a migration warning.
func TestPR44Round4UndeclaredVendorURLCannotSelectJenkins(t *testing.T) {
	for _, format := range []struct{ name, body, source, idKey, urlKey, suffix string }{
		{
			name: parse.FormatCEF, body: pr44CEF, source: "ngfw.checkpoint",
			idKey: "signature", urlKey: " request=", suffix: " msg=blocked request",
		},
		{
			name: parse.FormatLEEF, body: pr44LEEF + "^sev=8", source: "ngfw.usergate",
			idKey: "event_id", urlKey: "^url=", suffix: "^msg=blocked request",
		},
	} {
		for _, request := range []struct{ name, path string }{
			{"ordinary_control", "/account"},
			{"credentials", "/credentials"},
			{"configure", "/configure"},
		} {
			body := format.body + format.urlKey + "https://example.test" + request.path + format.suffix
			t.Run(format.name+"/"+request.name+"/declared_control", func(t *testing.T) {
				events := wafHTTPBatchAs(t, "/ingest/syslog", body, "192.0.2.20:31000", format.name)
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one genuine vendor event", len(events))
				}
				e := events[0]
				if e.Source != format.source || e.SourceClass != "ngfw" || e.Action != "session.deny" || e.Outcome != "deny" || e.Attrs[format.idKey] != "100" || e.SrcIP != "203.0.113.50" || e.Object != "https://example.test"+request.path {
					t.Fatalf("invalid vendor-record fixture: %+v", e)
				}
			})
			for _, envelope := range []struct{ name, prefix string }{
				{"raw", ""},
				{"pri_only", "<134>"},
				{"rfc3164_app", "<134>Nov  1 12:00:00 edge-fw exporter[42]: "},
				{"rfc3164_without_app", "<134>Nov  1 12:00:00 edge-fw "},
				{"rfc5424", "<134>1 2026-11-01T12:00:00Z edge-fw exporter 42 - - "},
			} {
				t.Run(format.name+"/"+request.name+"/"+envelope.name, func(t *testing.T) {
					logs := pr44Round3CaptureWarnings(t)
					line := envelope.prefix + body
					events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", "")
					if len(events) != 1 {
						t.Fatalf("accepted=%d, want one searchable undeclared record", len(events))
					}
					e := events[0]
					if e.SourceClass != "syslog" || !strings.HasPrefix(e.Action, "syslog.") || e.Outcome != "unknown" {
						t.Errorf("request URL selected a native vendor parser: source=%q class=%q action=%q outcome=%q", e.Source, e.SourceClass, e.Action, e.Outcome)
					}
					warnings := strings.Count(logs.String(), `"msg":"необъявленный формат:`)
					if warnings != 1 || undeclaredFormatTotal.Load() != 1 {
						t.Errorf("lost migration warning: warnings=%d metric=%d, want one each", warnings, undeclaredFormatTotal.Load())
					}
					if e.Raw != line || e.Attrs["peer"] != "192.0.2.20" {
						t.Error("raw evidence or transport peer changed")
					}
				})
			}
		}
	}
}
