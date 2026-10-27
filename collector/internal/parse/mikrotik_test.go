package parse

import "testing"

func TestSyslogISOHeader(t *testing.T) {
	s, err := ParseSyslog("<135>2026-10-27T23:42:55.0019+0300 MikroTik dhcp,info dhcp1 assigned 192.168.12.5 for 7C:C2:55:4E:CC:A6 seq-pc")
	if err != nil {
		t.Fatal(err)
	}
	if s.Hostname != "MikroTik" || s.Timestamp.IsZero() || s.Timestamp.UTC().Hour() != 20 || s.Timestamp.Year() != 2026 {
		t.Fatalf("header: %+v", s)
	}
	if s.Message != "dhcp,info dhcp1 assigned 192.168.12.5 for 7C:C2:55:4E:CC:A6 seq-pc" {
		t.Fatalf("msg: %q", s.Message)
	}
	// rsyslog ForwardFormat: зона с двоеточием, тег с PID
	s, _ = ParseSyslog("<38>2026-10-27T23:42:55.001234+03:00 web-01 sshd[2211]: Failed password for root from 203.0.113.42 port 22 ssh2")
	if s.Hostname != "web-01" || s.AppName != "sshd" || s.ProcID != "2211" || s.Timestamp.UTC().Hour() != 20 {
		t.Fatalf("rsyslog iso: %+v", s)
	}
}

func TestMikroTik(t *testing.T) {
	cases := []struct {
		line, action, outcome, actor, src, dst, obj string
		dport                                       uint16
	}{
		{"<134>Oct 27 23:50:01 MikroTik system,info,account user admin logged in from 192.168.12.122 via ssh", "auth.login", "success", "admin", "192.168.12.122", "", "", 0},
		{"<132>Oct 27 23:50:02 MikroTik system,error,critical login failure for user root from 203.0.113.9 via ssh", "auth.login", "failure", "root", "203.0.113.9", "", "", 0},
		{"<134>Oct 27 23:50:03 MikroTik firewall,info drop-input: in:ether1 out:(unknown 0), connection-state:new src-mac 00:11:22:33:44:55, proto TCP (SYN), 203.0.113.9:4444->185.25.9.1:22, len 60", "net.firewall", "deny", "", "203.0.113.9", "185.25.9.1", "", 22},
		{"<134>Oct 27 23:50:04 MikroTik dhcp,info Local assigned 192.168.12.5 for 7C:C2:55:4E:CC:A6 DESKTOP-1", "dhcp.assign", "success", "", "", "", "192.168.12.5", 0},
		{"<134>Oct 27 23:50:05 MikroTik dhcp,info Local deassigned 192.168.12.5 from 7C:C2:55:4E:CC:A6", "dhcp.release", "success", "", "", "", "192.168.12.5", 0},
		{"<134>Oct 27 23:50:06 MikroTik system,info filter rule changed by admin", "system.config", "success", "admin", "", "", "filter rule changed by admin", 0},
		// bsd-syslog=yes: без топиков, уровень в PRI, время ISO
		{"<134>2026-10-27T23:48:00.0001+0300 MikroTik Local assigned 192.168.12.119 for A4:CF:12:FB:7B:DA fish1", "dhcp.assign", "success", "", "", "", "192.168.12.119", 0},
		{"<134>2026-10-27T23:48:00.0000+0300 MikroTik Local deassigned 192.168.12.119 for A4:CF:12:FB:7B:DA fish1", "dhcp.release", "success", "", "", "", "192.168.12.119", 0},
		{"<134>2026-10-27T23:45:15.0000+0300 MikroTik user admin logged out from 192.168.0.103 via ssh", "auth.logout", "success", "admin", "192.168.0.103", "", "", 0},
		{"<131>2026-10-27T23:45:15.0000+0300 MikroTik login failure for user root from 203.0.113.9 via ssh", "auth.login", "failure", "root", "203.0.113.9", "", "", 0},
		{"<134>2026-10-27T23:45:15.0000+0300 MikroTik drop-input: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.9:4444->185.25.9.1:22, len 60", "net.firewall", "deny", "", "203.0.113.9", "185.25.9.1", "", 22},
	}
	for _, c := range cases {
		sl, _ := ParseSyslog(c.line)
		e, ok := ParseMikroTik(sl)
		if !ok {
			t.Fatalf("not recognised: %s", c.line)
		}
		if e.Action != c.action || e.Outcome != c.outcome || e.ActorName != c.actor || e.SrcIP != c.src || e.DstIP != c.dst || e.Object != c.obj || e.DstPort != c.dport {
			t.Fatalf("%s\n got %+v", c.line, e)
		}
		if e.Source != "net.routeros" || e.Node != "MikroTik" {
			t.Fatalf("source/node: %+v", e)
		}
	}
	fw, _ := ParseSyslog("<134>Oct 27 23:50:03 MikroTik firewall,info drop-input: in:ether1 out:(unknown 0), proto TCP (SYN), 203.0.113.9:4444->185.25.9.1:22, len 60")
	e, _ := ParseMikroTik(fw)
	if e.Proto != "tcp" || e.SrcPort != 4444 || e.Bytes != 60 || e.Attrs["in"] != "ether1" || e.Attrs["prefix"] != "drop-input" || e.Attrs["flags"] != "SYN" {
		t.Fatalf("firewall fields: %+v", e)
	}
	// Не RouterOS: нет известного топика
	if _, ok := ParseMikroTik(Syslog{Message: "foo,bar something happened"}); ok {
		t.Fatal("foreign comma list must not be RouterOS")
	}
	if _, ok := ParseMikroTik(Syslog{Message: "Accepted publickey for devops from 10.0.0.5 port 2 ssh2"}); ok {
		t.Fatal("plain text must not be RouterOS")
	}
	if _, ok := ParseMikroTik(Syslog{Message: "pam_unix(sudo:session): session opened for user root by admin(uid=0)"}); ok {
		t.Fatal("sudo line must not be RouterOS")
	}
	if e, ok := ParseMikroTik(Syslog{Message: "dhcp,warning Local offering lease 192.168.12.7 for 00:11:22:33:44:55 without success", Hostname: "MikroTik"}); !ok || e.Action != "dhcp.event" || e.Severity != 4 {
		t.Fatalf("dhcp warning: %+v", e)
	}
}
