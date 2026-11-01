package main

import (
	"testing"

	"github.com/devitex-soft/argus/collector/internal/listen"
	"github.com/devitex-soft/argus/collector/internal/normalize"
	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Разборщик выбирается по объявлению источника: SD [argus format=…] в заголовке
// RFC 5424, иначе peer.Format (SYSLOG_PEER_FORMAT, files[].format). Без объявления —
// syslog и счётчик argus_collector_undeclared_format_total (переходный релиз).
func TestDeclaredFormatSelectsParser(t *testing.T) {
	const cef = "CEF:0|Check Point|VPN-1 & FireWall-1|R81|100|deny|8|src=203.0.113.50 dst=192.0.2.10 act=deny"
	const coraza = `{"level":"error","logger":"http.handlers.waf","msg":"[client \"203.0.113.9\"] Coraza: Access denied with code 403 (phase 2). [file \"x\"] [id \"949110\"] [msg \"Inbound Anomaly Score Exceeded\"] [severity \"emergency\"] [hostname \"172.19.0.4\"] [uri \"/.env\"] [unique_id \"decl-1\"]"}`
	n := &normalize.Normalizer{}
	for _, tc := range []struct {
		name, line, peerFormat, wantClass string
		undeclared                        bool
	}{
		{"cef объявлен адресом", cef, parse.FormatCEF, "ngfw", false},
		{"cef объявлен SD", `<134>1 2026-11-01T10:00:00Z fw-01 exporter - - [argus format="cef"] ` + cef, "", "ngfw", false},
		{"cef без объявления — syslog и счётчик", cef, "", "syslog", true},
		{"coraza объявлен SD агента", `<134>1 2026-11-01T10:00:00Z waf-01 caddy - - [argus format="waf-coraza"] ` + coraza, "", "waf", false},
		{"coraza без объявления — syslog и счётчик", coraza, "", "syslog", true},
		{"SD сильнее адреса: cef-отправитель объявил coraza", `<134>1 2026-11-01T10:00:00Z waf-01 caddy - - [argus format="waf-coraza"] ` + coraza, parse.FormatCEF, "waf", false},
		{"объявлен cef, строка Coraza — не WAF", coraza, parse.FormatCEF, "syslog", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := undeclaredFormatTotal.Load()
			e, ok := parseSyslogLine(n, nil, tc.line, listen.Peer{Addr: "192.0.2.30", Transport: "udp", Format: tc.peerFormat})
			if !ok || e.SourceClass != tc.wantClass {
				t.Fatalf("класс %q, ожидался %q (ok=%v): %+v", e.SourceClass, tc.wantClass, ok, e)
			}
			if got := undeclaredFormatTotal.Load() > before; got != tc.undeclared {
				t.Errorf("счётчик необъявленного формата: вырос=%v, ожидалось %v", got, tc.undeclared)
			}
		})
	}
}

func TestParsePeerFormats(t *testing.T) {
	f, err := parse.ParsePeerFormats("10.0.0.5=cef, 10.1.0.0/16=leef,10.1.2.0/24=waf-coraza,::ffff:10.9.0.0/112=cef")
	if err != nil {
		t.Fatal(err)
	}
	for addr, want := range map[string]string{"10.0.0.5": "cef", "10.1.9.9": "leef", "10.1.2.3": "waf-coraza", "10.9.0.1": "cef", "10.2.0.1": "", "bad": ""} {
		if got := f.Lookup(addr); got != want {
			t.Errorf("Lookup(%s)=%q, want %q", addr, got, want)
		}
	}
	for _, bad := range []string{"10.0.0.5=modsecurity", "10.0.0.5", "fe80::1%eth0=cef", "nonsense=cef"} {
		if _, err := parse.ParsePeerFormats(bad); err == nil {
			t.Errorf("ParsePeerFormats(%q) принят", bad)
		}
	}
}
