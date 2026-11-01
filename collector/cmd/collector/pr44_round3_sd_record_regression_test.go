package main

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// RFC 5424 has an explicit MSG boundary. Structured-data parameter values
// before that boundary may contain request text, including complete records.
// They are not the CEF/LEEF TAG consumed by the RFC 3164 parser.
func TestPR44Round3StructuredDataCannotSupplyApplicationRecord(t *testing.T) {
	for _, format := range []struct{ name, record string }{
		{"cef", pr44CEF + " unused=fixture"},
		{"leef", pr44LEEF + "^unused=fixture"},
	} {
		for _, declaration := range []struct{ name, configured, sd string }{
			{"configured", format.name, ""},
			{"authenticated_agent_sd", "", fmt.Sprintf(`[argus format="%s"]`, format.name)},
		} {
			t.Run(format.name+"/"+declaration.name, func(t *testing.T) {
				const message = "exporter health check failed"
				line := fmt.Sprintf(`<134>1 2026-11-01T12:00:00Z edge-fw exporter 42 - %s[context@32473 request="%s"] %s`, declaration.sd, format.record, message)
				sl, err := parse.ParseSyslog(line)
				if err != nil || sl.Format != "rfc5424" || sl.Message != message || sl.Structured["context@32473.request"] != format.record {
					t.Fatalf("invalid structured-data fixture: err=%v syslog=%+v", err, sl)
				}
				events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", declaration.configured)
				if len(events) != 1 {
					t.Fatalf("accepted=%d, want one searchable diagnostic", len(events))
				}
				e := events[0]
				if e.SourceClass != "syslog" || e.Action != "syslog.exporter" || e.Outcome != "unknown" || e.Attrs["signature"] != "" || e.Attrs["event_id"] != "" {
					t.Errorf("SD value became an application event: class=%q action=%q outcome=%q signature=%q event_id=%q", e.SourceClass, e.Action, e.Outcome, e.Attrs["signature"], e.Attrs["event_id"])
				}
				if e.Object != message || e.Attrs["context@32473.request"] != format.record || e.Raw != line {
					t.Error("diagnostic message or its structured context was lost")
				}
			})
		}
	}
}
