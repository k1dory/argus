package parse

import "testing"

// An accepted interface-qualified setting must not silently become a setting
// for every interface. Rejecting scoped configuration is also safe if it is
// unsupported; ordinary unscoped CIDRs must continue matching scoped peers.
func TestPeerZonesDoNotWidenConfiguredInterfaceScope(t *testing.T) {
	fallback, err := ParsePeerZones("fe80::/64=UTC")
	if err != nil {
		t.Fatal(err)
	}
	if zone := fallback.Lookup("fe80::59%eth1"); zone == nil || zone.String() != "UTC" {
		t.Fatalf("unscoped CIDR must match a scoped peer: %v", zone)
	}

	zones, err := ParsePeerZones("fe80::/64=UTC,fe80::59%eth0=Europe/Moscow,fe80::59%eth1=Asia/Tokyo")
	if err != nil {
		// An explicit configuration error is preferable to silently applying
		// eth0's timezone to another sender. No configuration was installed.
		return
	}
	for _, tc := range []struct {
		peer, want string
	}{
		{"fe80::59%eth0", "Europe/Moscow"},
		{"fe80::59%eth1", "Asia/Tokyo"},
		{"fe80::59%eth2", "UTC"},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			zone := zones.Lookup(tc.peer)
			if zone == nil || zone.String() != tc.want {
				t.Fatalf("accepted scoped configuration matched another interface: peer=%q zone=%v, want %s; preserve the scope or reject the configuration", tc.peer, zone, tc.want)
			}
		})
	}
}
