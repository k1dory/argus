package rules

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// INTERNAL_NETS accepts IPv4-mapped IPv6 CIDRs. Normalize the configured
// prefix and the event address consistently: otherwise an accepted own subnet
// never matches, even when both strings use the same mapped representation.
func TestPR105InternalModifierMatchesMappedCIDRs(t *testing.T) {
	for _, tc := range []struct {
		name, nets string
		inside     []string
		outside    []string
	}{
		{
			name: "mapped subnet", nets: "::ffff:192.0.2.0/120",
			inside:  []string{"192.0.2.0", "192.0.2.42", "192.0.2.255", "::ffff:192.0.2.42", "::FFFF:C000:22A"},
			outside: []string{"192.0.1.255", "192.0.3.0", "2001:db8::42"},
		},
		{
			name: "mapped host", nets: "::ffff:192.0.2.42/128",
			inside:  []string{"192.0.2.42", "::ffff:192.0.2.42"},
			outside: []string{"192.0.2.41", "192.0.2.43"},
		},
		{
			name: "ordinary IPv4 control", nets: "192.0.2.0/24",
			inside:  []string{"192.0.2.42", "::ffff:192.0.2.42"},
			outside: []string{"192.0.1.255", "192.0.3.0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INTERNAL_NETS", tc.nets)
			const yaml = "title: Internal address regression\nid: pr105-internal\nlevel: low\ndetection:\n  selection:\n    src.ip|internal: %t\n  condition: selection\n"
			internal := load(t, fmt.Sprintf(yaml, true))
			external := load(t, fmt.Sprintf(yaml, false))
			firewall, err := LoadFile("../../../rules/fw-inbound-deny-burst.yml")
			if err != nil {
				t.Fatal(err)
			}
			check := func(ip string, wantInternal bool) {
				t.Helper()
				event := &model.Event{Action: "net.firewall", Outcome: "deny", SrcIP: ip, DstPort: 443}
				if got := internal.Match(event); got != wantInternal {
					t.Errorf("INTERNAL_NETS=%q src=%q: internal=true matches %t, want %t", tc.nets, ip, got, wantInternal)
				}
				if got := external.Match(event); got != !wantInternal {
					t.Errorf("INTERNAL_NETS=%q src=%q: internal=false matches %t, want %t", tc.nets, ip, got, !wantInternal)
				}
				if got := firewall.Match(event); got != !wantInternal {
					t.Errorf("INTERNAL_NETS=%q src=%q: firewall external-scan selection=%t, want %t", tc.nets, ip, got, !wantInternal)
				}
			}
			for _, ip := range tc.inside {
				check(ip, true)
			}
			for _, ip := range tc.outside {
				check(ip, false)
			}
		})
	}
}
