package eval

import (
	"net/netip"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/rules"
)

// An interface zone is valid in an IPv6 event address and is retained by
// normalized-event ingestion. It must not turn a link-local/own source into
// an external T1595 scan. The old regex excluded fe80::42%eth0 as well.
func TestPR105FirewallKeepsZonedSourcesInternal(t *testing.T) {
	for _, tc := range []struct {
		name, nets, src string
		wantExternal    bool
	}{
		{"default link-local with zone", "", "fe80::42%eth0", false},
		{"default link-local control", "", "fe80::42", false},
		{"configured IPv6 subnet with zone", "2001:db8:105::/64", "2001:db8:105::42%eth0", false},
		{"configured IPv6 subnet control", "2001:db8:105::/64", "2001:db8:105::42", false},
		{"external zoned neighbor stays visible", "2001:db8:105::/64", "2001:db8:106::42%eth0", true},
		{"external IPv6 control", "", "2001:db8::42", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INTERNAL_NETS", tc.nets)
			if _, err := netip.ParseAddr(tc.src); err != nil {
				t.Fatalf("fixture must contain a valid address: %v", err)
			}
			rule, err := rules.LoadFile("../../../rules/fw-inbound-deny-burst.yml")
			if err != nil {
				t.Fatal(err)
			}
			events := pr76FirewallBurst(tc.src, "2001:db8:105::80", "")
			if got := Run([]*rules.Rule{rule}, events[:29]); len(got) != 0 {
				t.Fatalf("29 ports must remain below the threshold: %+v", got)
			}
			got := Run([]*rules.Rule{rule}, events)
			if !tc.wantExternal {
				if len(got) != 0 {
					t.Fatalf("own source %q escaped the internal filter and generated T1595: %+v", tc.src, got)
				}
				return
			}
			if len(got) != 1 || got[0].Key != tc.src || len(got[0].Events) != 30 {
				t.Fatalf("external source %q lost its scan detection/evidence: %+v", tc.src, got)
			}
		})
	}
}
