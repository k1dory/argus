package parse

import "testing"

// hostOf preserves the interface suffix of an IPv6 link-local sender.
// IPv4-mapped addresses are also accepted by ParsePeerZones, so configuration
// and transport addresses must use the same normalization before matching.
func TestPeerZonesMatchEquivalentTransportAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, spec, peer string
	}{
		{"link-local sender with interface", "fe80::/64=Europe/Moscow", "fe80::59%eth0"},
		{"mapped exact address", "::ffff:192.0.2.59=Europe/Moscow", "::ffff:192.0.2.59"},
		{"mapped subnet", "::ffff:192.0.2.0/120=Europe/Moscow", "192.0.2.59"},
		{"ordinary IPv4 control", "192.0.2.59=Europe/Moscow", "192.0.2.59"},
		{"ordinary IPv6 control", "2001:db8::/64=Europe/Moscow", "2001:db8::59"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			zones, err := ParsePeerZones(tc.spec)
			if err != nil {
				t.Fatalf("valid zone configuration was rejected: %v", err)
			}
			zone := zones.Lookup(tc.peer)
			if zone == nil || zone.String() != "Europe/Moscow" {
				t.Fatalf("SYSLOG_PEER_TZ=%q peer=%q resolved to %v; RFC3164 local time would be treated as UTC", tc.spec, tc.peer, zone)
			}
		})
	}
}
