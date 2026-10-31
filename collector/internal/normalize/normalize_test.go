package normalize

import (
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

func TestClassifyBuiltinAndOverride(t *testing.T) {
	n := &Normalizer{Rules: []SourceRule{{Vendor: "UserGate", Name: "ngfw.usergate", Class: "ngfw", PII: true}}}
	cases := []struct{ vendor, product, name, class string }{
		{"Check Point", "VPN-1 & FireWall-1", "ngfw.checkpoint", "ngfw"},
		{"Palo Alto Networks", "Cortex XDR", "edr.cortex", "edr"},
		{"Palo Alto Networks", "PAN-OS", "ngfw.panos", "ngfw"},
		{"KasperskyLab", "KATA", "edr.kaspersky", "edr"},
		{"Acme", "Widget", "syslog.acme", "syslog"},
	}
	for _, c := range cases {
		name, class, _ := n.Classify(c.vendor, c.product)
		if name != c.name || class != c.class {
			t.Errorf("%s/%s → %s/%s, want %s/%s", c.vendor, c.product, name, class, c.name, c.class)
		}
	}
	if _, _, pii := n.Classify("UserGate", "UTM"); !pii {
		t.Error("override pii flag lost")
	}
}

func TestFromCEFNormalizes(t *testing.T) {
	n := &Normalizer{}
	c, _ := parse.ParseCEF(`CEF:0|Check Point|FireWall-1|R81|Accept|Firewall|3|rt=1757066138000 src=10.20.4.31 spt=51234 dst=10.20.5.7 dpt=445 proto=TCP suser=svc-backup act=Accept externalId=8841 dvchost=fw-01`)
	e := n.FromCEF(c, parse.Syslog{}, "raw")
	if e.Source != "ngfw.checkpoint" || e.Action != "session.allow" || e.Outcome != "allow" {
		t.Fatalf("%+v", e)
	}
	if e.ActorName != "svc-backup" || e.ActorKind != "service" || e.DstPort != 445 || e.Proto != "tcp" || e.Node != "fw-01" {
		t.Fatalf("%+v", e)
	}
	if e.TS != "2025-09-05 09:55:38.000" {
		t.Fatalf("rt → ts: %s", e.TS)
	}
	if e.PII != 0 {
		t.Fatal("no e-mail → no pii")
	}
}

func TestPIIDetection(t *testing.T) {
	n := &Normalizer{}
	l, _ := parse.ParseLEEF("LEEF:1.0|Ideco|UTM|16|web|src=10.0.0.9\tuser=i.petrov@corp.local\taction=allow\turl=https://example.org")
	e := n.FromLEEF(l, parse.Syslog{}, "raw")
	if e.PII != 1 || e.Action != "session.allow" || e.Object != "https://example.org" {
		t.Fatalf("%+v", e)
	}
	sl, _ := parse.ParseSyslog("<14>1 2026-09-05T10:00:00Z hr-01 app - - - user +7 (912) 345-67-89 requested export")
	if n.FromSyslog(sl, "raw").PII != 1 {
		t.Fatal("phone in message must flag pii")
	}
}

func TestFromFlow(t *testing.T) {
	n := &Normalizer{}
	e := n.FromFlow(parse.Flow{SrcIP: "10.1.1.1", DstIP: "8.8.8.8", DstPort: 53, Proto: 17, Bytes: 120, Packets: 1}, "netflow.core", "10.0.0.254")
	if e.SourceClass != "netflow" || e.Proto != "udp" || e.Action != "flow" || e.Node != "10.0.0.254" {
		t.Fatalf("%+v", e)
	}
}

func TestFromWAF(t *testing.T) {
	n := &Normalizer{}
	w := parse.WAF{Product: "coraza", Time: "2026-09-13T12:00:02Z", ClientIP: "198.51.100.77", ClientPort: 40000, HostIP: "10.0.10.12", HostPort: 443,
		Method: "GET", URI: "/.git/config", Host: "git.corp.local", UserAgent: "zgrab", Status: 403, EngineMode: "On", UniqueID: "x1",
		Rules: []parse.WAFRule{{ID: "930130", Msg: "Restricted File Access Attempt", Severity: 2}}, Categories: []string{"lfi"}, MaxSeverity: 2, AnomalyIn: 5, Blocked: true, Final: true}
	e := n.FromWAF(w, "raw")
	if e.Source != "waf.coraza" || e.SourceClass != "waf" || e.Action != "http.attack" || e.Outcome != "deny" || e.Severity != 9 {
		t.Fatalf("%+v", e)
	}
	// без server_id узел пуст (заголовок Host — от клиента), адрес сервера — в dst_ip и server_addr
	if e.SrcIP != "198.51.100.77" || e.Node != "" || e.DstIP != "10.0.10.12" || e.Attrs["server_addr"] != "10.0.10.12" || e.Object != "GET /.git/config" || e.TS != "2026-09-13 12:00:02.000" {
		t.Fatalf("%+v", e)
	}
	if e.Attrs["category"] != "lfi" || e.Attrs["status"] != "403" || e.Attrs["rule_ids"] != "930130" || e.Attrs["anomaly_score"] != "5" || e.Attrs["user_agent"] != "zgrab" {
		t.Fatalf("attrs %+v", e.Attrs)
	}
	// приложение само ответило 403 без решения WAF — это не deny
	w.Blocked = false
	if e := n.FromWAF(w, "raw"); e.Outcome != "allow" {
		t.Fatalf("403 приложения не должен считаться блокировкой WAF: %+v", e)
	}
	// DetectionOnly: атака замечена, но пропущена — outcome allow, статус приложения сохраняется
	w.EngineMode, w.Status, w.Blocked = "DetectionOnly", 500, false
	e = n.FromWAF(w, "raw")
	if e.Outcome != "allow" || e.Attrs["status"] != "500" || e.Attrs["engine_mode"] != "DetectionOnly" {
		t.Fatalf("detect-only: %+v", e)
	}
	// без правил — обычный запрос
	w.Rules, w.Categories, w.MaxSeverity = nil, nil, -1
	if e := n.FromWAF(w, "raw"); e.Action != "http.request" || e.Severity != 0 {
		t.Fatalf("plain: %+v", e)
	}
}

// FromWAF ставит узлом только server_id (его задаёт оператор). [hostname]
// error-лога присылает клиент (у ModSecurity под Apache/nginx это заголовок
// Host): только в attrs.http_host, даже если это IP. Адрес сокета Coraza
// допускается в dst_ip/server_addr.
// Окончательный узел выбирает коллектор (cmd/collector wafNode).
func TestFromWAFNodeIsNameNotAddress(t *testing.T) {
	n := &Normalizer{}
	base := parse.WAF{Product: "coraza", ClientIP: "93.123.109.247", Method: "GET", URI: "/", Final: true, MaxSeverity: -1}
	for _, tc := range []struct {
		name                 string
		serverID, serverName string
		hostIP               string
		wantNode, wantAddr   string
		wantHTTPHost         string
	}{
		{"coraza: адрес контейнера с портом", "", "172.19.0.4:443", "", "", "172.19.0.4", ""},
		{"coraza: адрес без порта", "", "172.19.0.4", "", "", "172.19.0.4", ""},
		{"coraza: IPv6 в скобках", "", "[fd00::4]:443", "", "", "fd00::4", ""},
		{"modsecurity: [hostname] — Host от клиента, не узел", "", "web-01", "", "", "", "web-01"},
		{"атакующий подставил Host: dc01.corp", "", "dc01.corp", "", "", "", "dc01.corp"},
		{"имя с портом", "", "web-01:8443", "", "", "", "web-01:8443"},
		{"audit: server_id — узел", "waf-01", "172.19.0.4", "10.0.10.12", "waf-01", "10.0.10.12", ""},
		{"audit: host_ip без server_id — узел пуст", "", "", "10.0.10.12", "", "10.0.10.12", ""},
		{"ничего не названо", "", "", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := base
			w.ServerID, w.ServerName, w.HostIP, w.Host = tc.serverID, tc.serverName, tc.hostIP, "shop.example.org"
			e := n.FromWAF(w, "raw")
			if e.Node != tc.wantNode {
				t.Fatalf("node %q, ожидалось %q", e.Node, tc.wantNode)
			}
			if e.Attrs["server_addr"] != tc.wantAddr || e.DstIP != tc.wantAddr {
				t.Fatalf("server_addr %q / dst_ip %q, ожидалось %q", e.Attrs["server_addr"], e.DstIP, tc.wantAddr)
			}
			if e.Attrs["http_host"] != tc.wantHTTPHost {
				t.Fatalf("http_host %q, ожидалось %q", e.Attrs["http_host"], tc.wantHTTPHost)
			}
			if e.Attrs["host"] != "shop.example.org" {
				t.Fatalf("attrs.host — заголовок Host audit-лога как был: %+v", e.Attrs)
			}
		})
	}
}

func TestHostAddr(t *testing.T) {
	for in, want := range map[string]string{"172.19.0.4": "172.19.0.4", "172.19.0.4:443": "172.19.0.4", "[fd00::4]:443": "fd00::4", "fd00::4": "fd00::4",
		" 10.0.0.1 ": "10.0.0.1", "web-01": "", "web-01:8443": "", "": "", "999.1.1.1": ""} {
		got, ok := hostAddr(in)
		if got != want || ok != (want != "") {
			t.Errorf("hostAddr(%q) = %q,%v; ожидалось %q", in, got, ok, want)
		}
	}
}

func TestModSecurityHostCannotSupplyServerAddress(t *testing.T) {
	n := &Normalizer{}
	for _, host := range []string{"attacker.example", "203.0.113.7", "203.0.113.7:443", "[2001:db8::7]:443"} {
		for _, serverAddr := range []string{"", "10.0.10.12"} {
			w := parse.WAF{Product: "modsecurity", ServerName: host, HostIP: serverAddr, ServerID: "operator-waf", Final: true, MaxSeverity: -1}
			e := n.FromWAF(w, "raw")
			if e.Node != "operator-waf" || e.DstIP != serverAddr || e.Attrs["server_addr"] != serverAddr || e.Attrs["http_host"] != host {
				t.Errorf("Host=%q audit address=%q changed trusted identity/address: %+v", host, serverAddr, e)
			}
		}
	}
}
