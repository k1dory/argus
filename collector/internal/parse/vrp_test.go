package parse

import "testing"

func TestSyslogVRPHeaderWithYear(t *testing.T) {
	s, err := ParseSyslog("<189>Oct 27 2026 21:47:12 sw1.genomed.ru %%01CLI/5/LOGOUT(s):CID=0x80ca2713;The user succeeded in logging out of VTY0. (UserType=SSH, UserName=levadmin, Ip=185.25.9.57, VpnName=_public_, Reason=user request)")
	if err != nil {
		t.Fatal(err)
	}
	if s.Hostname != "sw1.genomed.ru" || s.Timestamp.Year() != 2026 || s.Timestamp.Hour() != 21 || s.Timestamp.Day() != 27 {
		t.Fatalf("header: %+v", s)
	}
	if s.Facility != 23 || s.Severity != 5 {
		t.Fatalf("pri: %+v", s)
	}
}

func TestVRP(t *testing.T) {
	cases := []struct {
		line, action, outcome, actor, src, obj string
		sev                                    uint8
	}{
		{"<189>Oct 27 2026 21:47:12 sw1 %%01CLI/5/LOGOUT(s):CID=0x80ca2713;The user succeeded in logging out of VTY0. (UserType=SSH, UserName=levadmin, Ip=185.25.9.57, VpnName=_public_, Reason=user request)", "auth.logout", "success", "levadmin", "185.25.9.57", "The user succeeded in logging out of VTY0.", 2},
		{"<189>Oct 27 2026 21:47:12 sw1 %%01CLI/5/LOGIN(s):CID=0x80ca2713;The user succeeded in logging in to VTY0. (UserType=SSH, UserName=levadmin, Ip=185.25.9.57, VpnName=_public_)", "auth.login", "success", "levadmin", "185.25.9.57", "The user succeeded in logging in to VTY0.", 2},
		{"<188>Oct 27 2026 21:47:12 sw1 %%01SSH/4/SSH_FAIL(l):CID=0x1;The SSH user failed to login. (ServiceType=stelnet, FailedReason=password error, UserName=root, Ip=203.0.113.9)", "auth.login", "failure", "root", "203.0.113.9", "The SSH user failed to login.", 5},
		{"<189>Oct 27 2026 21:47:12 sw1 %%01CLI/5/CMDRECORD(s):CID=0x80ca2713;Recorded command information. (Task=VTY0, Ip=185.25.9.57, VpnName=_public_, User=levadmin, AuthenticationMethod=\"Local-user\", Command=\"info-center loghost 192.168.0.170 port 5514\")", "system.command", "success", "levadmin", "185.25.9.57", "info-center loghost 192.168.0.170 port 5514", 2},
		{"<187>Oct 27 2026 21:47:12 sw1 %%01IFNET/3/LINK_STATE(l)[12]:The line protocol IP on the interface GE1/0/12 has entered the DOWN state.", "net.link", "failure", "", "", "The line protocol IP on the interface GE1/0/12 has entered the DOWN state.", 5},
		{"<190>Oct 27 2026 21:47:12 sw1 %%01OSPF/6/NBR_CHG_DOWN(l):CID=0x2;Neighbor state changed. (ProcessId=1, NeighborAddress=172.16.0.1, State=Down)", "vrp.ospf/nbr_chg_down", "unknown", "", "", "Neighbor state changed.", 1},
	}
	for _, c := range cases {
		sl, _ := ParseSyslog(c.line)
		e, ok := ParseVRP(sl)
		if !ok {
			t.Fatalf("not recognised: %s", c.line)
		}
		if e.Action != c.action || e.Outcome != c.outcome || e.ActorName != c.actor || e.SrcIP != c.src || e.Object != c.obj || e.Severity != c.sev {
			t.Fatalf("%s\n got %+v", c.line, e)
		}
		if e.Source != "net.vrp" || e.Node != "sw1" || e.Attrs["module"] == "" || e.Attrs["mnemonic"] == "" {
			t.Fatalf("source/node/attrs: %+v", e)
		}
	}
	if _, ok := ParseVRP(Syslog{Message: "user admin logged in from 1.2.3.4 via ssh"}); ok {
		t.Fatal("RouterOS line must not be VRP")
	}
}
