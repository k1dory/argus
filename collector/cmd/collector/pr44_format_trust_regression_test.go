package main

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

const pr44CEF = "CEF:0|Check Point|Firewall|1|100|deny|8|src=203.0.113.50 dst=192.0.2.10 act=deny"
const pr44LEEF = "LEEF:2.0|UserGate|NGFW|1|100|^|src=203.0.113.50^dst=192.0.2.10^action=deny"
const pr44Caddy = `{"level":"error","logger":"http.handlers.waf","msg":"[client \"203.0.113.50\"] Coraza: Access denied (phase 2). Header policy [file \"/etc/coraza/local.conf\"] [id \"1001\"] [msg \"Header policy\"] [severity \"critical\"] [hostname \"192.0.2.10\"] [uri \"/account\"] [unique_id \"pr44-format\"]"}`

// SYSLOG_PEER_FORMAT is operator configuration. Even an authenticated agent's
// SD cannot replace it; files[].format is the same boundary for file input.
func TestPR44ConfiguredFormatTakesPrecedenceOverSD(t *testing.T) {
	for _, tc := range []struct {
		format, body, source, action, ruleID string
	}{
		{parse.FormatCEF, pr44CEF, "ngfw.checkpoint", "session.deny", ""},
		{parse.FormatLEEF, pr44LEEF, "ngfw.usergate", "session.deny", ""},
		{parse.FormatWAFCoraza, pr44Caddy, "waf.coraza", "http.attack", "1001"},
	} {
		formats, err := parse.ParsePeerFormats("192.0.2.20=" + tc.format)
		if err != nil {
			t.Fatal(err)
		}
		peers := []listen.Peer{
			{Addr: "192.0.2.20", Transport: "udp", Format: formats.Lookup("192.0.2.20")},
			{Addr: "192.0.2.20", Transport: "tcp", Format: formats.Lookup("192.0.2.20")},
			{Addr: "192.0.2.20", Transport: "tls", CN: "agent-01", Format: formats.Lookup("192.0.2.20")},
		}
		if tc.format == parse.FormatWAFCoraza {
			peers = append(peers, listen.Peer{Addr: "waf.error", Transport: "file", Format: tc.format})
		}
		for _, peer := range peers {
			for _, sd := range []string{"", parse.FormatCEF, parse.FormatLEEF, parse.FormatWAFCoraza, "unknown-format"} {
				t.Run(tc.format+"/"+peer.Transport+"/sd="+sd, func(t *testing.T) {
					line := fmt.Sprintf(`<134>1 2026-11-01T12:00:00Z source-01 agent - - [argus format=%q] %s`, sd, tc.body)
					e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, peer)
					if !ok || e.Source != tc.source || e.Action != tc.action || e.Outcome != "deny" || e.SrcIP != "203.0.113.50" || e.Attrs["rule_ids"] != tc.ruleID {
						t.Fatalf("SD overrode configured format %q: accepted=%v source=%q action=%q outcome=%q src=%q rule_ids=%q", tc.format, ok, e.Source, e.Action, e.Outcome, e.SrcIP, e.Attrs["rule_ids"])
					}
				})
			}
		}
	}
}

// UDP, plain TCP and server-authenticated TLS do not authenticate an agent.
// Merely naming a format in RFC 5424 SD must not authorize a WAF/NGFW parser.
func TestPR44UntrustedPeerCannotSelfDeclareFormat(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "tls"} {
		for _, tc := range []struct{ format, body string }{
			{parse.FormatCEF, pr44CEF},
			{parse.FormatLEEF, pr44LEEF},
			{parse.FormatWAFCoraza, pr44Caddy},
		} {
			t.Run(transport+"/"+tc.format, func(t *testing.T) {
				line := fmt.Sprintf(`<134>1 2026-11-01T12:00:00Z claimed-agent app - - [argus format=%q] %s`, tc.format, tc.body)
				peer := listen.Peer{Addr: "198.51.100.20", Transport: transport}
				e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, peer)
				if !ok || e.SourceClass != "syslog" || e.Outcome != "unknown" || e.Attrs["rule_ids"] != "" {
					t.Fatalf("untrusted SD selected a privileged parser: accepted=%v class=%q action=%q outcome=%q rule_ids=%q", ok, e.SourceClass, e.Action, e.Outcome, e.Attrs["rule_ids"])
				}
			})
		}
	}
}

func TestPR44CEFPeerCannotPromotePayloadToWAFThroughSD(t *testing.T) {
	formats, err := parse.ParsePeerFormats("192.0.2.20=cef")
	if err != nil {
		t.Fatal(err)
	}
	peer := listen.Peer{Addr: "192.0.2.20", Transport: "tcp", Format: formats.Lookup("192.0.2.20")}
	line := `<134>1 2026-11-01T12:00:00Z claimed-waf app - - [argus format="waf-coraza"] ` + pr44Caddy
	e, ok := parseSyslogLine(&normalize.Normalizer{}, nil, line, peer)
	if !ok || e.SourceClass != "syslog" || e.Action == "http.attack" || e.Attrs["rule_ids"] != "" {
		t.Fatalf("CEF sender manufactured a WAF event through SD: accepted=%v class=%q action=%q rule_ids=%q", ok, e.SourceClass, e.Action, e.Attrs["rule_ids"])
	}
}
