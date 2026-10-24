package parse

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// Fuzz-тесты: парсеры не должны паниковать ни на каком входе.
// go test -run=^$ -fuzz=FuzzParseCEF -fuzztime=30s ./internal/parse

func FuzzParseCEF(f *testing.F) {
	for _, s := range []string{
		"CEF:0|Check Point|FW|R81|Accept|Firewall|0|src=10.0.0.1 dst=10.0.0.2 spt=1 dpt=2",
		"<134>1 2026-09-05T10:12:18Z fw CheckPoint - - - CEF:0|a|b|c|d|e|High|",
		"CEF:0|a\\|b|c|d|e|f|g|k=v\\=x k2=\\\\",
		"CEF:", "CEF:0|", "CEF:0|||||||", "noise",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, ok := ParseCEF(s)
		if ok && c.Ext == nil {
			t.Fatal("ok без Ext")
		}
	})
}

func FuzzParseLEEF(f *testing.F) {
	for _, s := range []string{
		"LEEF:2.0|UserGate|NGFW|7.1|deny|x5e|src=10.1.1.1^dst=8.8.8.8",
		"LEEF:1.0|Ideco|UTM|1|allow|src=1\tdst=2",
		"LEEF:2.0|a|b|c|d||k=v", "LEEF:2.0|a|b|c|d|xZZ|k=v", "LEEF:", "LEEF:1.0|", "LEEF:2.0|a|b|c|d|x|",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { ParseLEEF(s) })
}

func FuzzParseSyslog(f *testing.F) {
	for _, s := range []string{
		`<34>1 2026-09-14T12:00:00.123Z host app 123 ID47 [exampleSDID@32473 iut="3" eventSource="App"] msg`,
		`<34>1 - - - - - -`, `<34>Sep 14 12:00:00 host app[12]: msg`, `<>`, `<999>`, `<34>1 `,
		`<34>1 2026-09-14T12:00:00Z h a - - [x y="\"] m`, `<34>1 2026-09-14T12:00:00Z h a - - [x`, "",
		"1757066138.123      5 10.0.0.1 TCP_DENIED/403 0 GET http://x - HIER_NONE/- -",
		"Feb 05, 2026 10:12:18 AM job/deploy/ #42 Started by user i.petrov",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sl, _ := ParseSyslog(s)
		ParseSquid(sl.Message, sl.Hostname)
		ParseJenkins(sl.Message, sl.Hostname)
	})
}

func FuzzNetFlow(f *testing.F) {
	f.Add(buildV9())
	v9 := buildV9()
	f.Add(v9[:20])
	f.Add(v9[:len(v9)-3])
	ipfix := binary.BigEndian.AppendUint16(nil, 10)
	ipfix = binary.BigEndian.AppendUint16(ipfix, 40)
	ipfix = append(ipfix, make([]byte, 12)...)
	ipfix = binary.BigEndian.AppendUint16(ipfix, 2)
	ipfix = binary.BigEndian.AppendUint16(ipfix, 16)
	ipfix = append(ipfix, 1, 44, 0, 2, 0x80, 8, 0, 4, 0, 0, 0, 9, 0, 82, 0xff, 0xff)
	f.Add(ipfix)
	f.Add([]byte{0, 10, 0, 0})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		d := NewDecoder()
		// один и тот же пакет дважды: второй раз шаблон уже есть и данные декодируются
		d.Decode("10.0.0.1", pkt)
		d.Decode("10.0.0.1", pkt)
	})
}

func FuzzWAFErrorLine(f *testing.F) {
	for _, s := range []string{
		"2026/09/14 12:00:00 [error] 1#1: *2 ModSecurity: Access denied with code 403 (phase 2). Matched \"Operator `Ge' with parameter `5' against variable `TX:ANOMALY_SCORE' (Value: `5' ) [file \"/rules/REQUEST-949-BLOCKING-EVALUATION.conf\"] [line \"80\"] [id \"949110\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 5)\"] [severity \"2\"] [tag \"attack-sqli\"] [hostname \"x\"] [uri \"/a\"] [unique_id \"1\"], client: 10.0.0.1",
		`{"level":"error","ts":1757066138.5,"logger":"http.handlers.waf","msg":"Coraza: Warning. [client \"10.0.0.1\"] [file \"x\"] [id \"942100\"] [msg \"SQLi\"] [severity \"critical\"] [tag \"attack-sqli\"]"}`,
		`ModSecurity: `, `Coraza: Warning. [file "`, `ModSecurity: Access denied with redirect [id "1`, `{"msg":`, "",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		IsWAFErrorLine(s)
		ParseWAFErrorLine(s)
	})
}

func FuzzWAFAudit(f *testing.F) {
	for _, s := range []string{
		`{"transaction":{"time_stamp":"Sun Sep 14 12:00:00 2026","client_ip":"10.0.0.1","client_port":1,"host_ip":"10.0.0.2","host_port":80,"unique_id":"a","request":{"method":"GET","uri":"/","headers":{"Host":"x","User-Agent":"y"}},"response":{"http_code":403},"producer":{"modsecurity":"ModSecurity v3","secrules_engine":"Enabled"}},"messages":[{"message":"m","details":{"ruleId":"949110","msg":"Inbound Anomaly Score Exceeded (Total Score: 10)","severity":"2","tags":["attack-sqli"]}}]}`,
		`{"transaction":{"timestamp":"2026-09-14T12:00:00Z","client_ip":"1.1.1.1","request":{"uri":"/"},"response":{"status":200},"producer":{"connector":"coraza","rule_engine":"On"},"messages":[{"message":"x","data":{"id":942100,"msg":"m","severity":2,"tags":["attack-xss"]}}]}}`,
		`{"transaction":{}}`, `{"transaction":{"client_ip":"x","messages":[{"data":{"id":null,"severity":"critical"}}]}}`, `[`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		IsWAFAudit(b)
		ParseWAFAudit(b)
	})
}

func FuzzK8s(f *testing.F) {
	for _, s := range []string{
		`{"kind":"EventList","items":[{"auditID":"1","stage":"ResponseComplete","verb":"create","user":{"username":"system:serviceaccount:x:y"},"sourceIPs":["10.0.0.1"],"objectRef":{"resource":"clusterrolebindings","apiGroup":"rbac.authorization.k8s.io","name":"n"},"responseStatus":{"code":201},"requestObject":{"roleRef":{"name":"cluster-admin"}},"stageTimestamp":"2026-09-14T12:00:00Z"}]}`,
		`{"kind":"Event","verb":"get","user":{"username":"u"},"stage":"Panic"}`,
		`{"kind":"Event"}`, `{"items":[{"verb":"list","stageTimestamp":"9999-99-99"}]}`, `[]`, `{`, ``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		evs, _ := ParseK8sAudit(b, "c")
		for _, e := range evs {
			if e.Attrs == nil {
				t.Fatal("Ensure не отработал")
			}
		}
	})
}

func FuzzGitLab(f *testing.F) {
	for _, s := range []string{
		`{"id":1,"author_name":"a","entity_path":"g/p","event_type":"project_created","ip_address":"1.1.1.1","created_at":"2026-09-14T12:00:00Z","details":{"change":"visibility","from":"private","to":"public"}}`,
		`{"object_kind":"pipeline","object_attributes":{"status":"failed","ref":"main"},"user":{"username":"u","email":"u@x.io"},"project":{"path_with_namespace":"g/p"},"runner":{"is_shared":true}}`,
		`{"event_name":"user_add_to_group","user_username":"u","group_path":"g"}`,
		`{"object_kind":"build","build_status":"success"}`, `{}`, `{"id":"x"}`, `[`, ``,
		`{"type":"PUSH_ARTIFACT","occur_at":1757066138,"operator":"robot$ci","event_data":{"repository":{"repo_full_name":"a/b"},"resources":[{"tag":"v1","scan_overview":{"x":{"severity":"Critical","summary":{"total":3}}}}]}}`,
		`{"app":{"metadata":{"name":"a","namespace":"argocd"},"spec":{"project":"p"},"status":{"health":{"status":"Degraded"}}},"action":"OnSyncFailed","timestamp":"2026-09-14T12:00:00Z"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseGitLab(b)
		ParseHarbor(b)
		ParseArgoCD(b)
	})
}

func FuzzPcap(f *testing.F) {
	full := pcapWithTCP(20, 0x50)
	f.Add(full)
	f.Add(pcapWithTCP(8, 0x50))  // TCP с 8 байтами L4 — раньше паника на l4[12]
	f.Add(pcapWithTCP(12, 0x50)) // 12 байт
	f.Add(pcapWithTCP(24, 0xf0)) // data offset за пределами
	f.Add(full[:24])
	f.Fuzz(func(t *testing.T, b []byte) {
		PcapPayloads(bytes.NewReader(b), func([]byte, string, uint16) {})
	})
}

// pcapWithTCP: один Ethernet/IPv4/TCP-пакет с l4Len байтами после IP-заголовка.
func pcapWithTCP(l4Len int, doffByte byte) []byte {
	l4 := make([]byte, l4Len)
	if l4Len > 12 {
		l4[12] = doffByte
	}
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 20, 4, 31, 10, 0, 0, 254}
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	frame := append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00}, append(ip, l4...)...)
	pcap := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	pcap = binary.LittleEndian.AppendUint16(pcap, 2)
	pcap = binary.LittleEndian.AppendUint16(pcap, 4)
	pcap = append(pcap, make([]byte, 8)...)
	pcap = binary.LittleEndian.AppendUint32(pcap, 65535)
	pcap = binary.LittleEndian.AppendUint32(pcap, 1)
	pcap = binary.LittleEndian.AppendUint32(pcap, 1757066138)
	pcap = binary.LittleEndian.AppendUint32(pcap, 0)
	pcap = binary.LittleEndian.AppendUint32(pcap, uint32(len(frame)))
	pcap = binary.LittleEndian.AppendUint32(pcap, uint32(len(frame)))
	return append(pcap, frame...)
}

func TestPcapShortTCPNoPanic(t *testing.T) {
	for _, n := range []int{8, 10, 12, 13, 19, 20} {
		calls := 0
		if err := PcapPayloads(bytes.NewReader(pcapWithTCP(n, 0x50)), func([]byte, string, uint16) { calls++ }); err != nil {
			t.Errorf("l4=%d: %v", n, err)
		}
		if calls != 0 {
			t.Errorf("l4=%d: пустой TCP не должен давать полезной нагрузки", n)
		}
	}
	got := 0
	pk := pcapWithTCP(24, 0x50)
	copy(pk[len(pk)-4:], "data")
	PcapPayloads(bytes.NewReader(pk), func(p []byte, _ string, _ uint16) { got = len(p) })
	if got != 4 {
		t.Errorf("payload TCP: %d, want 4", got)
	}
	_ = strings.TrimSpace
}
