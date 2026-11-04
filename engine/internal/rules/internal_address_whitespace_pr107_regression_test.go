package rules

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
)

// Companion control for collector/internal/normalize's PR #107 scope test.
// The rule engine already trims IP fields; keep that accepted-input contract
// explicit so fixing collector scope does not silently change rule matching.
func TestPR107InternalModifierAcceptsPaddedMappedAndZonedAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, nets, inside, outside string
	}{
		{"mapped CIDR", "::ffff:192.0.2.0/120", "::ffff:192.0.2.42", "198.51.100.9"},
		{"default link-local zone", "", "fe80::42%eth0", "2001:db8:108::9"},
		{"configured IPv6 zone", "2001:db8:107::/64", "2001:db8:107::42%eth0", "2001:db8:108::9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INTERNAL_NETS", tc.nets)
			const definition = "title: Padded address contract\nid: pr107-internal-padding\nlevel: low\ndetection:\n  selection:\n    src.ip|internal: %t\n  condition: selection\n"
			internal := load(t, fmt.Sprintf(definition, true))
			external := load(t, fmt.Sprintf(definition, false))
			for _, input := range []struct {
				address string
				want    bool
			}{
				{tc.inside, true},
				{" \t" + tc.inside + " \t", true},
				{tc.outside, false},
				{" \t" + tc.outside + " \t", false},
				{" \tnot-an-address \t", false},
			} {
				event := &model.Event{SrcIP: input.address}
				if got := internal.Match(event); got != input.want {
					t.Errorf("INTERNAL_NETS=%q src=%q: internal=%t, want %t", tc.nets, input.address, got, input.want)
				}
				if got := external.Match(event); got != !input.want {
					t.Errorf("INTERNAL_NETS=%q src=%q: external=%t, want %t", tc.nets, input.address, got, !input.want)
				}
			}
		})
	}
}
