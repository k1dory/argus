package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// A configured CEF/LEEF sender can also forward a diagnostic or a JSON log.
// The declaration must not promote a record inside a request-derived field.
// In raw/PRI-only JSON, the first space is not a HOSTNAME/MSG boundary: adding
// a synthetic PRI does not make the JSON prefix a valid RFC 3164 header.
// The existing round-5 Caddy-context test uses waf-coraza; this exercises the
// cef/leef fallback contract, including both the TAG and MSG acceptance paths.
func TestPR44Round4JSONSpaceCannotPromoteCEFLEEF(t *testing.T) {
	const wafMsg = `[client "203.0.113.50"] Coraza: Access denied (phase 2). Header policy [file "/etc/coraza/local.conf"] [id "1001"] [msg "Header policy"] [severity "critical"] [hostname "192.0.2.10"] [uri "/account"] [unique_id "pr44-round4-json"]`
	for _, format := range []struct{ name, record, source, idKey string }{
		{
			name: parse.FormatCEF, source: "ngfw.fortigate", idKey: "signature",
			record: "CEF:0|Fortinet|FortiGate|7|9001|allow|1|src=198.51.100.99 dst=192.0.2.99 act=allow dvchost=forged-node unused=fixture",
		},
		{
			name: parse.FormatLEEF, source: "ngfw.usergate", idKey: "event_id",
			record: "LEEF:2.0|UserGate|NGFW|7|9001|^|src=198.51.100.99^dst=192.0.2.99^action=allow^sev=1^devName=forged-node^unused=fixture",
		},
	} {
		t.Run(format.name+"/genuine_record_control", func(t *testing.T) {
			events := wafHTTPBatchAs(t, "/ingest/syslog", format.record, "192.0.2.20:31000", format.name)
			if len(events) != 1 {
				t.Fatalf("accepted=%d, want one genuine vendor record", len(events))
			}
			e := events[0]
			if e.Source != format.source || e.SourceClass != "ngfw" || e.Action != "session.allow" || e.Outcome != "allow" || e.Attrs[format.idKey] != "9001" || e.Node != "forged-node" || e.SrcIP != "198.51.100.99" {
				t.Fatalf("invalid vendor-record fixture: %+v", e)
			}
		})
		for _, container := range []struct{ name, logger, msg, wantWAF string }{
			{name: "ordinary_json"},
			{name: "caddy_request_context", logger: "http.handlers.waf", msg: wafMsg, wantWAF: "1"},
		} {
			for _, request := range []struct{ name, prefix string }{
				{"no_space_control", "Fixture/1.0/"},
				{"space_before_marker", "Fixture/1.0 "},
				{"space_before_client_tag", "Fixture/1.0 Forwarded: "},
			} {
				// Keep request context first. Its value is one JSON string, even
				// when a User-Agent contains a space or text resembling a TAG.
				body, err := json.Marshal(struct {
					Request string `json:"request"`
					Logger  string `json:"logger,omitempty"`
					Msg     string `json:"msg,omitempty"`
				}{request.prefix + format.record, container.logger, container.msg})
				if err != nil {
					t.Fatal(err)
				}
				if container.wantWAF != "" {
					if w, ok := parse.ParseCorazaLine(string(body)); !ok || !w.Blocked || !w.Final || len(w.Rules) != 1 || w.Rules[0].ID != "1001" {
						t.Fatalf("invalid Caddy fixture: accepted=%v waf=%+v", ok, w)
					}
				}
				for _, envelope := range []struct{ name, prefix string }{
					{"raw", ""},
					{"pri_only", "<134>"},
					{"rfc3164_control", "<134>Nov  1 12:00:00 relay-01 exporter[42]: "},
					{"no_pri_rfc3164_control", "Nov  1 12:00:00 relay-01 exporter[42]: "},
					{"rfc5424_control", "<134>1 2026-11-01T12:00:00Z relay-01 exporter 42 - - "},
				} {
					t.Run(format.name+"/"+container.name+"/"+request.name+"/"+envelope.name, func(t *testing.T) {
						line := envelope.prefix + string(body)
						events := wafHTTPBatchAs(t, "/ingest/syslog", line, "192.0.2.20:31000", format.name)
						if len(events) != 1 {
							t.Fatalf("accepted=%d, want one searchable JSON record", len(events))
						}
						e := events[0]
						if e.SourceClass != "syslog" || !strings.HasPrefix(e.Action, "syslog.") || e.Outcome != "unknown" {
							t.Errorf("JSON request data became a vendor event: source=%q class=%q action=%q outcome=%q", e.Source, e.SourceClass, e.Action, e.Outcome)
						}
						if e.Attrs["signature"] != "" || e.Attrs["event_id"] != "" || e.SrcIP != "" || e.DstIP != "" || e.Node == "forged-node" {
							t.Errorf("JSON request data supplied security fields: signature=%q event_id=%q src=%q dst=%q node=%q", e.Attrs["signature"], e.Attrs["event_id"], e.SrcIP, e.DstIP, e.Node)
						}
						if e.Attrs["waf_unparsed"] != container.wantWAF {
							t.Errorf("waf_unparsed=%q, want %q", e.Attrs["waf_unparsed"], container.wantWAF)
						}
						if e.Raw != line || e.Attrs["peer"] != "192.0.2.20" {
							t.Error("raw evidence or transport peer changed")
						}
					})
				}
			}
		}
	}
}
