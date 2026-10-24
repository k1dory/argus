package parse

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func TestSyslog5424WithSD(t *testing.T) {
	line := `<134>1 2026-09-05T10:12:18.684Z fw-01 checkpoint 2211 ID47 [origin ip="10.0.0.1" software="fw1"] Accept src=10.0.1.5`
	s, err := ParseSyslog(line)
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != "rfc5424" || s.Hostname != "fw-01" || s.AppName != "checkpoint" || s.ProcID != "2211" {
		t.Fatalf("header: %+v", s)
	}
	if s.Structured["origin.ip"] != "10.0.0.1" || s.Structured["origin.software"] != "fw1" {
		t.Fatalf("sd: %+v", s.Structured)
	}
	if s.Message != "Accept src=10.0.1.5" || s.Facility != 16 || s.Severity != 6 {
		t.Fatalf("msg/pri: %+v", s)
	}
}

func TestSyslog3164(t *testing.T) {
	s, err := ParseSyslog("<38>Sep  5 10:12:18 web-01 sshd[2211]: Failed password for root from 203.0.113.42 port 22 ssh2")
	if err != nil {
		t.Fatal(err)
	}
	if s.Format != "rfc3164" || s.Hostname != "web-01" || s.AppName != "sshd" || s.ProcID != "2211" {
		t.Fatalf("%+v", s)
	}
	if s.Message != "Failed password for root from 203.0.113.42 port 22 ssh2" {
		t.Fatalf("msg: %q", s.Message)
	}
}

func TestCEFCheckPoint(t *testing.T) {
	line := `<134>1 2026-09-05T10:12:18Z fw-01 CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Accept|Firewall|0|rt=1757066138000 src=10.20.4.31 spt=51234 dst=10.20.5.7 dpt=445 proto=TCP suser=svc-backup act=Accept cs1Label=Rule cs1=SMB\=internal externalId=8841 dvchost=fw-01 msg=trailing value with spaces`
	c, ok := ParseCEF(line)
	if !ok {
		t.Fatal("cef not detected")
	}
	if c.Vendor != "Check Point" || c.Product != "VPN-1 & FireWall-1" || c.Name != "Firewall" || c.SignatureID != "Accept" {
		t.Fatalf("header: %+v", c)
	}
	if c.Ext["src"] != "10.20.4.31" || c.Ext["dpt"] != "445" || c.Ext["suser"] != "svc-backup" {
		t.Fatalf("ext: %+v", c.Ext)
	}
	if c.Ext["cs1"] != "SMB=internal" {
		t.Fatalf("escaped '=' lost: %q", c.Ext["cs1"])
	}
	if c.Ext["msg"] != "trailing value with spaces" {
		t.Fatalf("multiword value: %q", c.Ext["msg"])
	}
}

func TestCEFSeverityWords(t *testing.T) {
	c, _ := ParseCEF(`CEF:0|Kaspersky|KATA|5.1|EDR_DETECT|Suspicious LSASS access|High|dhost=WKS-2214 dproc=procdump64.exe filePath=C:\\Users\\a\\AppData\\Local\\Temp\\pd\\procdump64.exe act=Detect`)
	if c.Severity != 8 || c.Ext["dproc"] != "procdump64.exe" {
		t.Fatalf("%+v", c)
	}
	if c.Ext["filePath"] != `C:\Users\a\AppData\Local\Temp\pd\procdump64.exe` {
		t.Fatalf("backslashes: %q", c.Ext["filePath"])
	}
}

func TestLEEF2(t *testing.T) {
	l, ok := ParseLEEF(`<13>Sep  5 10:12:18 ug-01 LEEF:2.0|UserGate|UTM|7.1|url_filter|x09|src=10.30.1.8	dst=91.108.4.1	dstPort=443	usrName=i.petrov@corp.local	url=https://t.me/	action=block	sev=6`)
	if !ok {
		t.Fatal("leef not detected")
	}
	if l.Vendor != "UserGate" || l.EventID != "url_filter" || l.Ext["usrName"] != "i.petrov@corp.local" || l.Ext["action"] != "block" {
		t.Fatalf("%+v", l)
	}
}

func TestLEEF1TabDelimited(t *testing.T) {
	l, ok := ParseLEEF("LEEF:1.0|Ideco|UTM|16|auth_fail|src=10.0.0.9\tuser=admin\tresult=failure")
	if !ok || l.Ext["result"] != "failure" || l.Ext["user"] != "admin" {
		t.Fatalf("%+v %v", l, ok)
	}
}

// Собираем пакет NetFlow v9: шаблон 256 и одну запись данных.
func buildV9() []byte {
	fields := [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {1, 4}, {2, 4}, {22, 4}, {21, 4}}
	tmpl := make([]byte, 0, 4+len(fields)*4)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 256)
	tmpl = binary.BigEndian.AppendUint16(tmpl, uint16(len(fields)))
	for _, f := range fields {
		tmpl = binary.BigEndian.AppendUint16(tmpl, f[0])
		tmpl = binary.BigEndian.AppendUint16(tmpl, f[1])
	}
	tset := binary.BigEndian.AppendUint16(nil, 0)
	tset = binary.BigEndian.AppendUint16(tset, uint16(4+len(tmpl)))
	tset = append(tset, tmpl...)

	rec := append([]byte{}, net.ParseIP("10.20.3.19").To4()...)
	rec = append(rec, net.ParseIP("91.108.4.1").To4()...)
	rec = binary.BigEndian.AppendUint16(rec, 51000)
	rec = binary.BigEndian.AppendUint16(rec, 443)
	rec = append(rec, 6)
	rec = binary.BigEndian.AppendUint32(rec, 42_000)
	rec = binary.BigEndian.AppendUint32(rec, 120)
	rec = binary.BigEndian.AppendUint32(rec, 1000) // first switched
	rec = binary.BigEndian.AppendUint32(rec, 6000) // last switched
	dset := binary.BigEndian.AppendUint16(nil, 256)
	dset = binary.BigEndian.AppendUint16(dset, uint16(4+len(rec)))
	dset = append(dset, rec...)

	hdr := binary.BigEndian.AppendUint16(nil, 9)
	hdr = binary.BigEndian.AppendUint16(hdr, 2)
	hdr = binary.BigEndian.AppendUint32(hdr, 10_000)     // sysUptime ms
	hdr = binary.BigEndian.AppendUint32(hdr, 1757066138) // unix secs
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = binary.BigEndian.AppendUint32(hdr, 7)
	pkt := append(hdr, tset...)
	return append(pkt, dset...)
}

func TestNetFlowV9Roundtrip(t *testing.T) {
	d := NewDecoder()
	flows, err := d.Decode("10.0.0.254", buildV9())
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 {
		t.Fatalf("flows: %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "10.20.3.19" || f.DstIP != "91.108.4.1" || f.SrcPort != 51000 || f.DstPort != 443 {
		t.Fatalf("addr: %+v", f)
	}
	if f.Proto != 6 || f.Bytes != 42_000 || f.Packets != 120 {
		t.Fatalf("counters: %+v", f)
	}
	if !f.End.After(f.Start) || f.End.Sub(f.Start).Milliseconds() != 5000 {
		t.Fatalf("times: %v %v", f.Start, f.End)
	}
	// данные раньше шаблона — молча ничего
	d2 := NewDecoder()
	pkt := buildV9()
	dataOnly := append(pkt[:20:20], pkt[20+4+4+9*4:]...)
	binary.BigEndian.PutUint16(dataOnly[2:4], 1)
	flows, _ = d2.Decode("10.0.0.254", dataOnly)
	if len(flows) != 0 {
		t.Fatalf("data before template must be dropped, got %d", len(flows))
	}
}

func TestIPFIXVariableLength(t *testing.T) {
	// шаблон: srcIPv4(8,4), dstPort(11,2), interfaceName(82, var)
	tmpl := binary.BigEndian.AppendUint16(nil, 300)
	tmpl = binary.BigEndian.AppendUint16(tmpl, 3)
	for _, f := range [][2]uint16{{8, 4}, {11, 2}, {82, 65535}} {
		tmpl = binary.BigEndian.AppendUint16(tmpl, f[0])
		tmpl = binary.BigEndian.AppendUint16(tmpl, f[1])
	}
	tset := binary.BigEndian.AppendUint16(nil, 2)
	tset = binary.BigEndian.AppendUint16(tset, uint16(4+len(tmpl)))
	tset = append(tset, tmpl...)
	rec := append([]byte{}, net.ParseIP("10.1.1.1").To4()...)
	rec = binary.BigEndian.AppendUint16(rec, 53)
	rec = append(rec, 4, 'e', 't', 'h', '0')
	dset := binary.BigEndian.AppendUint16(nil, 300)
	dset = binary.BigEndian.AppendUint16(dset, uint16(4+len(rec)))
	dset = append(dset, rec...)
	body := append(tset, dset...)
	hdr := binary.BigEndian.AppendUint16(nil, 10)
	hdr = binary.BigEndian.AppendUint16(hdr, uint16(16+len(body)))
	hdr = binary.BigEndian.AppendUint32(hdr, 1757066138)
	hdr = binary.BigEndian.AppendUint32(hdr, 1)
	hdr = binary.BigEndian.AppendUint32(hdr, 9)
	flows, err := NewDecoder().Decode("10.0.0.1", append(hdr, body...))
	if err != nil || len(flows) != 1 {
		t.Fatalf("%v %d", err, len(flows))
	}
	if flows[0].SrcIP != "10.1.1.1" || flows[0].DstPort != 53 || string(flows[0].Fields[82]) != "eth0" {
		t.Fatalf("%+v", flows[0])
	}
}

func TestK8sAuditRBAC(t *testing.T) {
	body := []byte(`{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[
	 {"level":"RequestResponse","auditID":"a1","stage":"ResponseComplete","requestURI":"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings","verb":"create",
	  "user":{"username":"oidc:i.petrov","groups":["dev"]},"sourceIPs":["10.0.5.5"],"userAgent":"kubectl/v1.30",
	  "objectRef":{"resource":"clusterrolebindings","name":"argo-admin","apiGroup":"rbac.authorization.k8s.io"},
	  "responseStatus":{"code":201},"requestObject":{"roleRef":{"name":"cluster-admin"},"subjects":[{"kind":"ServiceAccount","name":"argo","namespace":"deploy"}]},
	  "stageTimestamp":"2026-09-05T04:38:07.120000Z","annotations":{"authorization.k8s.io/decision":"allow"}},
	 {"level":"Metadata","auditID":"a2","stage":"RequestReceived","verb":"get","user":{"username":"system:serviceaccount:kube-system:coredns"},"stageTimestamp":"2026-09-05T04:38:08Z"}
	]}`)
	events, err := ParseK8sAudit(body, "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("RequestReceived must be skipped, got %d", len(events))
	}
	e := events[0]
	if e.Action != "k8s.create.clusterrolebindings" || e.ActorName != "oidc:i.petrov" || e.ActorKind != "user" {
		t.Fatalf("%+v", e)
	}
	if e.Attrs["role_ref"] != "cluster-admin" || e.Severity != 8 || e.Outcome != "success" || e.Node != "prod" {
		t.Fatalf("rbac enrichment: %+v", e)
	}
	if e.TS != "2026-09-05 04:38:07.120" {
		t.Fatalf("ts: %s", e.TS)
	}
}

func TestGitLabForms(t *testing.T) {
	audit, err := ParseGitLab([]byte(`{"id":1,"author_name":"i.petrov","entity_path":"sec/argus-rules","entity_type":"Project","event_type":"project_access_token_created","ip_address":"10.0.5.5","created_at":"2026-09-05T04:01:38Z","details":{"author_name":"i.petrov","custom_message":"Created project access token"}}`))
	if err != nil || audit.Action != "gitlab.project_access_token_created" || audit.SrcIP != "10.0.5.5" || audit.Object != "sec/argus-rules" {
		t.Fatalf("%v %+v", err, audit)
	}
	job, err := ParseGitLab([]byte(`{"object_kind":"build","ref":"main","build_name":"build:push","build_stage":"deploy","build_status":"success","user":{"name":"CI","username":"project_7_bot","email":"bot@corp.local"},"project":{"path_with_namespace":"sec/argus"},"runner":{"description":"runner-07","is_shared":true}}`))
	if err != nil || job.Action != "gitlab.build.success" || job.ActorKind != "service" || job.Attrs["runner_shared"] != "true" || job.PII != 1 {
		t.Fatalf("%v %+v", err, job)
	}
	if _, err := ParseGitLab([]byte(`{"hello":"world"}`)); err == nil {
		t.Fatal("unknown form must fail")
	}
}

func TestSquidNative(t *testing.T) {
	e, ok := ParseSquid("1757066138.684    215 10.30.1.8 TCP_DENIED/403 3985 CONNECT t.me:443 i.petrov@corp.local HIER_NONE/- text/html", "proxy-01")
	if !ok || e.Source != "ngfw.squid" || e.Action != "session.deny" || e.Object != "t.me:443" || e.PII != 1 || e.Bytes != 3985 {
		t.Fatalf("%v %+v", ok, e)
	}
	if _, ok := ParseSquid("something else entirely", ""); ok {
		t.Fatal("не squid")
	}
}

func TestHarborWebhook(t *testing.T) {
	e, err := ParseHarbor([]byte(`{"type":"DELETE_ARTIFACT","occur_at":1757066138,"operator":"i.petrov","event_data":{"resources":[{"digest":"sha256:abc","tag":"1.4.0","resource_url":"harbor.corp/sec/argus:1.4.0"}],"repository":{"name":"argus","namespace":"sec","repo_full_name":"sec/argus","repo_type":"private"}}}`))
	if err != nil || e.Action != "harbor.delete_artifact" || e.Severity != 5 || e.Object != "sec/argus" || e.Attrs["tag"] != "1.4.0" {
		t.Fatalf("%v %+v", err, e)
	}
}

func TestArgoCDNotification(t *testing.T) {
	e, err := ParseArgoCD([]byte(`{"app":{"metadata":{"name":"payments","namespace":"argocd"},"spec":{"project":"prod","source":{"repoURL":"git@git:apps.git","path":"payments"}},"status":{"sync":{"status":"OutOfSync","revision":"deadbeef"},"health":{"status":"Degraded"}}},"action":"OnSyncFailed","user":"i.petrov","timestamp":"2026-09-05T04:38:07Z"}`))
	if err != nil || e.Action != "argocd.syncfailed" || e.Outcome != "failure" || e.Object != "prod/payments" || e.Attrs["revision"] != "deadbeef" {
		t.Fatalf("%v %+v", err, e)
	}
}

func TestJenkinsAudit(t *testing.T) {
	e, ok := ParseJenkins("Sep 5, 2026 10:12:18 AM job/deploy/configure Job configuration updated by user i.petrov", "ci-01")
	if !ok || e.Action != "jenkins.configure" || e.ActorName != "i.petrov" || e.Severity != 5 {
		t.Fatalf("%v %+v", ok, e)
	}
}

// pcap: один UDP-пакет с syslog-строкой, собранный вручную
func TestPcapUDPPayload(t *testing.T) {
	payload := []byte("<134>1 2026-09-05T10:12:18Z fw-01 CheckPoint - - - CEF:0|Check Point|FW|R81|Accept|Firewall|0|src=10.0.0.1")
	udp := binary.BigEndian.AppendUint16(nil, 51000)
	udp = binary.BigEndian.AppendUint16(udp, 514)
	udp = binary.BigEndian.AppendUint16(udp, uint16(8+len(payload)))
	udp = binary.BigEndian.AppendUint16(udp, 0)
	udp = append(udp, payload...)
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 20, 4, 31, 10, 0, 0, 254}
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(udp)))
	frame := append([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00}, append(ip, udp...)...)
	pcap := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	pcap = binary.LittleEndian.AppendUint16(pcap, 2)
	pcap = binary.LittleEndian.AppendUint16(pcap, 4)
	pcap = binary.LittleEndian.AppendUint32(pcap, 0)
	pcap = binary.LittleEndian.AppendUint32(pcap, 0)
	pcap = binary.LittleEndian.AppendUint32(pcap, 65535)
	pcap = binary.LittleEndian.AppendUint32(pcap, 1)
	pcap = binary.LittleEndian.AppendUint32(pcap, 1757066138)
	pcap = binary.LittleEndian.AppendUint32(pcap, 0)
	pcap = binary.LittleEndian.AppendUint32(pcap, uint32(len(frame)))
	pcap = binary.LittleEndian.AppendUint32(pcap, uint32(len(frame)))
	pcap = append(pcap, frame...)
	var got []string
	var src string
	var port uint16
	err := PcapPayloads(bytesReader(pcap), func(p []byte, s string, d uint16) { got = append(got, string(p)); src, port = s, d })
	if err != nil || len(got) != 1 || got[0] != string(payload) || src != "10.20.4.31" || port != 514 {
		t.Fatalf("%v %d %q %s %d", err, len(got), got, src, port)
	}
}

// RFC 3164 без года: «Dec 31» в первых числах января — прошлый год, а не будущее.
func TestSyslog3164YearRollover(t *testing.T) {
	now = func() time.Time { return time.Date(2027, 1, 2, 3, 0, 0, 0, time.UTC) }
	defer func() { now = time.Now }()
	s, err := ParseSyslog("<34>Dec 31 23:00:00 host app[1]: bye")
	if err != nil {
		t.Fatal(err)
	}
	if s.Timestamp.Year() != 2026 || s.Timestamp.Month() != time.December || s.Hostname != "host" || s.Message != "bye" {
		t.Errorf("year rollover: %v %+v", s.Timestamp, s)
	}
	// в пределах суток вперёд — текущий год (часовые пояса источника)
	s, _ = ParseSyslog("<34>Jan  2 20:00:00 host app: x")
	if s.Timestamp.Year() != 2027 {
		t.Errorf("+17h должен остаться в текущем году: %v", s.Timestamp)
	}
	s, _ = ParseSyslog("<34>Jan  1 10:00:00 host app: x")
	if s.Timestamp.Year() != 2027 {
		t.Errorf("вчера — текущий год: %v", s.Timestamp)
	}
}
