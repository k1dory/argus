package parse

import (
	"testing"
	"time"
)

func TestQNAP(t *testing.T) {
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return time.Date(2026, 10, 30, 21, 45, 0, 0, time.UTC) }
	msk, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		line, action, outcome, actor, src, obj, log string
		sev                                         uint8
	}{
		{`<30>Oct 31 00:40:15 QNAP-2 qulogd[16075]: conn log: Users: admin, Source IP: 192.168.0.108, Computer name: ---, Connection type: HTTP, Accessed resources: Administration, Action: Login Success`, "auth.login", "success", "admin", "192.168.0.108", "Administration", "access", 1},
		{`<30>Oct 31 00:40:09 QNAP-2 qulogd[16075]: conn log: Users: admin, Source IP: 192.168.0.108, Computer name: ---, Connection type: HTTP, Accessed resources: ---, Action: Logout`, "auth.logout", "success", "admin", "192.168.0.108", "", "access", 1},
		{`<28>Oct 31 00:41:00 QNAP-2 qulogd[16075]: conn log: Users: guest, Source IP: 203.0.113.9, Computer name: ---, Connection type: SMB, Accessed resources: ---, Action: Login Fail`, "auth.login", "failure", "guest", "203.0.113.9", "", "access", 5},
		{`<30>Oct 31 00:42:55 QNAP-2 qulogd[16075]: conn log: Users: erp_read, Source IP: 192.168.0.254, Computer name: localhost, Connection type: FTP, Accessed resources: erp_genomed/landing-journal/2026/2/17303/17303-file_49bfc6.jpg, Action: Read`, "file.read", "success", "erp_read", "192.168.0.254", "erp_genomed/landing-journal/2026/2/17303/17303-file_49bfc6.jpg", "access", 1},
		// запятая в пути не ломает разбор полей
		{`<30>Oct 31 00:44:00 QNAP-2 qulogd[16075]: conn log: Users: i.petrov, Source IP: 192.168.12.40, Computer name: ws-40, Connection type: SMB, Accessed resources: Public/отчёт, итог.xlsx, Action: Delete`, "file.delete", "success", "i.petrov", "192.168.12.40", "Public/отчёт, итог.xlsx", "access", 1},
		{`<30>Oct 31 00:43:18 QNAP-2 qulogd[16075]: event log: Users: admin, Source IP: 192.168.0.108, Computer name: ---, Application: Users, Category: General, Content: [Users] Created user "bkp".`, "system.config", "success", "admin", "192.168.0.108", `[Users] Created user "bkp".`, "event", 4},
		{`<28>Oct 31 00:45:00 QNAP-2 qulogd[16075]: event log: Users: System, Source IP: 127.0.0.1, Computer name: localhost, Application: Storage & Snapshots, Category: Disk, Content: [Storage & Snapshots] Host: Disk 3: Medium error. Run a bad block scan on the drive.`, "storage.event", "failure", "System", "127.0.0.1", "[Storage & Snapshots] Host: Disk 3: Medium error. Run a bad block scan on the drive.", "event", 4},
	}
	for _, c := range cases {
		sl, _ := ParseSyslog(c.line)
		sl = sl.InZone(msk)
		e, ok := ParseQNAP(sl)
		if !ok {
			t.Fatalf("not recognised: %s", c.line)
		}
		if e.Action != c.action || e.Outcome != c.outcome || e.ActorName != c.actor || e.SrcIP != c.src || e.Object != c.obj || e.Severity != c.sev || e.Attrs["log"] != c.log {
			t.Fatalf("%s\n got %+v", c.line, e)
		}
		if e.Source != "nas.qnap" || e.SourceClass != "storage" || e.Node != "QNAP-2" {
			t.Fatalf("source/node: %+v", e)
		}
	}
	// Местное время QNAP (МСК) переводится в UTC: 00:40:15 31.10 МСК = 21:40:15 30.10 UTC.
	sl, _ := ParseSyslog(cases[0].line)
	e, _ := ParseQNAP(sl.InZone(msk))
	if e.TS != "2026-10-30 21:40:15.000" {
		t.Fatalf("ts: %s", e.TS)
	}
}

func TestQNAPNotOther(t *testing.T) {
	sl, _ := ParseSyslog("<30>Oct 31 00:40:15 host sshd[1]: conn log: Users: a, Source IP: 1.2.3.4")
	if _, ok := ParseQNAP(sl); ok {
		t.Fatal("чужое приложение распознано как QNAP")
	}
	sl, _ = ParseSyslog("<30>Oct 31 00:40:15 QNAP-2 qulogd[1]: something else")
	if _, ok := ParseQNAP(sl); ok {
		t.Fatal("неизвестное сообщение qulogd распознано")
	}
}

func TestInZone(t *testing.T) {
	defer func(f func() time.Time) { now = f }(now)
	now = func() time.Time { return time.Date(2026, 10, 30, 21, 45, 0, 0, time.UTC) }
	msk, _ := time.LoadLocation("Europe/Moscow")
	// RFC 5424 с поясом не меняется
	sl, _ := ParseSyslog("<30>1 2026-10-30T21:40:15+03:00 h app - - - msg")
	if got := sl.InZone(msk).Timestamp; !got.Equal(time.Date(2026, 10, 30, 18, 40, 15, 0, time.UTC)) {
		t.Fatalf("5424: %v", got)
	}
	// Huawei с годом в заголовке — тоже без пояса
	sl, _ = ParseSyslog("<189>Oct 27 2026 21:47:12 sw1 %%01CLI/5/LOGOUT(s):x")
	if got := sl.InZone(msk).Timestamp; !got.Equal(time.Date(2026, 10, 27, 18, 47, 12, 0, time.UTC)) {
		t.Fatalf("vrp: %v", got)
	}
	// без пояса — как было (UTC)
	sl, _ = ParseSyslog("<30>Oct 30 21:40:15 h app: msg")
	if got := sl.InZone(nil).Timestamp; !got.Equal(time.Date(2026, 10, 30, 21, 40, 15, 0, time.UTC)) {
		t.Fatalf("nil zone: %v", got)
	}
}

func TestPeerZones(t *testing.T) {
	z, err := ParsePeerZones(" 192.168.0.59=Europe/Moscow, 10.10.10.0/24=Asia/Yekaterinburg ,10.10.10.39=UTC")
	if err != nil {
		t.Fatal(err)
	}
	if l := z.Lookup("192.168.0.59"); l == nil || l.String() != "Europe/Moscow" {
		t.Fatalf("exact: %v", l)
	}
	if l := z.Lookup("10.10.10.5"); l == nil || l.String() != "Asia/Yekaterinburg" {
		t.Fatalf("cidr: %v", l)
	}
	if l := z.Lookup("10.10.10.39"); l == nil || l.String() != "UTC" {
		t.Fatalf("narrowest: %v", l)
	}
	if z.Lookup("192.168.0.60") != nil || z.Lookup("file:/x") != nil {
		t.Fatal("лишнее совпадение")
	}
	for _, bad := range []string{"192.168.0.59", "x=Europe/Moscow", "1.2.3.4=Mars/Base"} {
		if _, err := ParsePeerZones(bad); err == nil {
			t.Fatalf("%q принято", bad)
		}
	}
	if z, err := ParsePeerZones(""); err != nil || len(z) != 0 {
		t.Fatal("пустая строка")
	}
}
