package parse

import "testing"

// Формат linkDown_active/linkDown_clear из документации Huawei:
// https://info.support.huawei.com/network/ptmngsys/Web/tsrev_ce/en/content/ce/26_edesk_dc_multicast_Pixelation_occurs/edesk_dc_multicast_Pixelation_occurs_edesk001.html
// В свободном тексте нет up/down: состояние находится в параметрах и суффиксе
// мнемоники. PR #101 впервые направляет эти mixed-case события в ParseVRP.
func TestPR101VRPLinkAlarmOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name, body, state, outcome string
	}{
		{
			"down",
			"%%01IFNET/2/linkDown_active(l):CID=0x807a0408-alarmID=0x08520003;The interface status changes. (ifName=10GE1/0/1, AdminStatus=UP, OperStatus=DOWN, Reason=Interface physical link is down, mainIfname=10GE1/0/1)",
			"active", "failure",
		},
		{
			"restored",
			"%%01IFNET/2/linkDown_clear(l):CID=0x807a0408-alarmID=0x08520003-clearType=service_resume;The interface status changes. (ifName=10GE1/0/1, AdminStatus=UP, OperStatus=UP, Reason=Interface physical link is up, mainIfname=10GE1/0/1)",
			"clear", "success",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sl, err := ParseSyslog("<186>Nov  1 2026 12:00:00 switch-01 " + tc.body)
			if err != nil {
				t.Fatal(err)
			}
			e, ok := ParseVRP(sl)
			if !ok || e.Source != "net.vrp" || e.Action != "net.link" {
				t.Fatalf("not a VRP link event: ok=%v source=%q action=%q", ok, e.Source, e.Action)
			}
			if e.Attrs["alarm_state"] != tc.state || e.Attrs["alarm"] != "linkDown" {
				t.Fatalf("alarm metadata: %v", e.Attrs)
			}
			if e.Outcome != tc.outcome {
				t.Errorf("link alarm %q: outcome=%q, want %q (OperStatus=%q)", tc.state, e.Outcome, tc.outcome, e.Attrs["operstatus"])
			}
		})
	}
}
