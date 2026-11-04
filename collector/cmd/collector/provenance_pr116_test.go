package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/model"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Все зарегистрированные HTTP-входы с настоящими парсерами; вместо очереди —
// захват батча. Запросы выполняются через ServeHTTP, без сокетов и ClickHouse.
func TestPR116HTTPProvenanceAtEveryRoute(t *testing.T) {
	const sender = "192.0.2.40"
	const forged = `"attrs":{"peer":"192.0.2.99","peer_cn":"forged-cn","scope":"internal","transport":"internal","ts_original":"forged-ts","pe\u0000er":"192.0.2.98","sc\u0080ope":"outbound"}`
	for _, tc := range []struct {
		name, path, body, format, source, scope string
	}{
		{"events", "/ingest/events", `{"source":"fixture.agent","src_ip":"198.51.100.7","dst_ip":"10.20.0.8",` + forged + `}`, "", "fixture.agent", "inbound"},
		{"cef", "/ingest/syslog", "CEF:0|Check Point|VPN-1|1|1|deny|5|src=198.51.100.7 dst=10.20.0.8 peer=192.0.2.99 peer_cn=forged-cn scope=internal transport=internal ts_original=forged-ts", parse.FormatCEF, "ngfw.checkpoint", "inbound"},
		{"leef", "/ingest/syslog", "LEEF:1.0|UserGate|NGFW|7|deny|src=198.51.100.7\tdst=10.20.0.8\tpeer=192.0.2.99\tpeer_cn=forged-cn\tscope=internal\ttransport=internal\tts_original=forged-ts", parse.FormatLEEF, "ngfw.usergate", "inbound"},
		{"syslog", "/ingest/syslog", `<134>1 - fixture-host app - - [argus peer="192.0.2.99" peer_cn="forged-cn" scope="internal" transport="internal" ts_original="forged-ts"] hello`, "", "syslog.app", ""},
		{"k8s", "/ingest/k8s-audit", `{"kind":"Event","verb":"get","sourceIPs":["198.51.100.7"],"annotations":{"peer":"192.0.2.99","peer_cn":"forged-cn"},` + forged + `}`, "", "k8s.audit", ""},
		{"gitlab", "/ingest/gitlab", `{"event_name":"user_create",` + forged + `}`, "", "gitlab.audit", ""},
		{"harbor", "/ingest/harbor", `{"type":"PUSH_ARTIFACT",` + forged + `}`, "", "harbor.audit", ""},
		{"argocd", "/ingest/argocd", `{"app":{"metadata":{"name":"fixture-app"}},"action":"sync",` + forged + `}`, "", "argocd.audit", ""},
		{"waf", "/ingest/modsecurity", `{"transaction":{"client_ip":"198.51.100.7","host_ip":"10.20.0.8","request":{"uri":"/"}},` + forged + `}`, "", "waf.modsecurity", "inbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, batch := range []bool{true, false} {
				norm := &normalize.Normalizer{}
				var accepted []model.Event
				h := &listen.HTTPHandlers{
					Token: "pr116-dummy-token",
					ParseLine: func(line string, peer listen.Peer) (model.Event, bool) {
						peer.Format = tc.format
						return parseSyslogLine(norm, nil, line, peer)
					},
					ParseWAFAudit: func(obj json.RawMessage, peer listen.Peer) (model.Event, bool) {
						return wafAuditEvent(norm, obj, peer)
					},
				}
				if batch {
					h.EmitBatch = func(_ context.Context, events []model.Event) error {
						accepted = append(accepted, events...)
						return nil
					}
				} else {
					h.Emit = func(e model.Event) { accepted = append(accepted, e) }
				}
				req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
				req.RemoteAddr = sender + ":40000"
				req.Header.Set("X-Argus-Token", h.Token)
				req.Header.Set("X-Forwarded-For", "192.0.2.99")
				res := httptest.NewRecorder()
				h.Mux().ServeHTTP(res, req)
				if res.Code != http.StatusAccepted || len(accepted) != 1 {
					t.Fatalf("batch=%v: status=%d events=%d body=%s", batch, res.Code, len(accepted), res.Body.String())
				}
				e := accepted[0]
				if e.Source != tc.source || e.Attrs["peer"] != sender {
					t.Fatalf("batch=%v: source=%q peer=%q", batch, e.Source, e.Attrs["peer"])
				}
				// Проверяем границу до emitHTTPBatch: присланное происхождение
				// уже снято, повторная чистка также не должна его восстановить.
				e.Sanitize()
				for _, key := range []string{"peer_cn", "scope", "transport", "ts_original"} {
					if value, exists := e.Attrs[key]; exists {
						t.Errorf("batch=%v: untrusted attrs.%s survived HTTP: %q", batch, key, value)
					}
				}
				setScope(e.Attrs, e.SrcIP, e.DstIP, norm.FlowScope)
				if got := e.Attrs["scope"]; got != tc.scope {
					t.Errorf("batch=%v: scope=%q, want %q", batch, got, tc.scope)
				}
			}
		})
	}
}

// CEF/LEEF по syslog и из файла могут содержать произвольные ключи.
// Проверяем цепочку dispatcher → skew.apply → setScope, которую использует emit.
func TestPR116SyslogAndFileProvenance(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "tls", "file"} {
		for _, format := range []string{parse.FormatCEF, parse.FormatLEEF} {
			t.Run(transport+"/"+format, func(t *testing.T) {
				peer := listen.Peer{Addr: "192.0.2.40", Transport: transport, Format: format}
				if transport == "tls" {
					peer.CN = "verified-fixture-cn"
				}
				// Для файла source="192.0.2.40" позволяет объявить формат
				// тем же SYSLOG_PEER_FORMAT, что использует parseLine.
				line := "CEF:0|Check Point|VPN-1|1|1|deny|5|src=198.51.100.7 dst=10.20.0.8 peer=192.0.2.99 peer_cn=forged-cn scope=internal transport=internal ts_original=forged-ts"
				if format == parse.FormatLEEF {
					line = "LEEF:1.0|UserGate|NGFW|7|deny|src=198.51.100.7\tdst=10.20.0.8\tpeer=192.0.2.99\tpeer_cn=forged-cn\tscope=internal\ttransport=internal\tts_original=forged-ts\tpe\xc2\xc2\x00\x80\x80er=192.0.2.98"
				}
				norm := &normalize.Normalizer{}
				e, ok := parseSyslogLine(norm, nil, line, peer)
				if !ok || e.SourceClass != "ngfw" || e.Raw != line {
					t.Fatalf("fixture did not reach the declared parser: ok=%v event=%+v", ok, e)
				}
				if e.Attrs["peer"] != peer.Addr || e.Attrs["peer_cn"] != peer.CN {
					t.Fatalf("sender identity came from the payload: %q", e.Attrs)
				}
				e.Attrs["transport"] = peer.Transport // emit stamps the listener transport.
				newSkewWatch(0).apply(&e, time.Now()) // Also strips ts_original when disabled.
				setScope(e.Attrs, e.SrcIP, e.DstIP, norm.FlowScope)
				e.Sanitize()
				if e.Attrs["scope"] != "inbound" || e.Attrs["transport"] != transport || e.Attrs["ts_original"] != "" || e.Attrs["peer"] != peer.Addr || e.Attrs["peer_cn"] != peer.CN {
					t.Fatalf("provenance changed before queueing: %q", e.Attrs)
				}
			})
		}
	}
}

// Повторное вычисление направления должно сохранить результат FromFlow,
// включая свои публичные сети, IPv6, NAT и остальные атрибуты парсера.
func TestPR116ScopePreservesInternalParserResults(t *testing.T) {
	norm := &normalize.Normalizer{
		InternalNets: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("fd00::/8")},
		NATAddrs:     []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
	}
	for _, tc := range []struct{ name, src, dst, want string }{
		{"inbound", "198.51.100.7", "192.0.2.8", "inbound"},
		{"outbound_nat", "192.0.2.1", "198.51.100.7", "outbound"},
		{"internal", "192.0.2.8", "192.0.2.9", "internal"},
		{"external", "198.51.100.7", "203.0.113.8", "external"},
		{"ipv6", "2001:db8::7", "fd00::8", "inbound"},
		{"no_src", "", "192.0.2.8", ""},
		{"no_dst", "192.0.2.8", "", ""},
		{"no_addresses", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := norm.FromFlow(parse.Flow{SrcIP: tc.src, DstIP: tc.dst, Proto: 6, TCPFlags: 2, Packets: 1, Bytes: 60}, "netflow.fixture", "192.0.2.254")
			// Уже выставленные коллектором атрибуты не относятся к scope.
			e.Attrs["transport"] = "udp"
			setScope(e.Attrs, e.SrcIP, e.DstIP, norm.FlowScope)
			if e.Attrs["scope"] != tc.want || e.Attrs["syn_only"] != "1" || e.Attrs["avg_pkt"] != "60" || e.Attrs["transport"] != "udp" {
				t.Fatalf("scope/flow metadata changed: %q", e.Attrs)
			}
			if tc.name == "outbound_nat" && e.Attrs["post_nat"] != "1" {
				t.Fatal("lost collector-derived NAT marker")
			}
			e.Attrs["scope"] = "forged"
			setScope(e.Attrs, e.SrcIP, e.DstIP, norm.FlowScope)
			if e.Attrs["scope"] != tc.want {
				t.Fatalf("supplied scope survived: %q", e.Attrs["scope"])
			}
			if tc.want == "" {
				if _, exists := e.Attrs["scope"]; exists {
					t.Fatal("scope must be absent without both addresses")
				}
			}
		})
	}
}
