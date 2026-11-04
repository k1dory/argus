package normalize

import (
	"fmt"
	"net/netip"
	"testing"
	"unicode"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

// Exercise both classification and the post_nat consumer. PR #107's padding
// regression covered scope, but not inPrefixes or Unicode whitespace.
func TestPR109ScopeAndPostNATTrimUnicodeWhitespace(t *testing.T) {
	padding := []string{""}
	var allSpaces string
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if unicode.IsSpace(r) {
			padding = append(padding, string(r))
			allSpaces += string(r)
		}
	}
	padding = append(padding, allSpaces)
	for _, tc := range []struct {
		name, prefix, inside, outside string
		configured                    bool
	}{
		{"default IPv4", "10.0.0.0/8", "10.20.30.40", "198.51.100.9", false},
		{"default IPv6 zone", "fe80::/10", "fe80::42%eth0", "2001:db8:110::9", false},
		{"custom replaces defaults", "192.0.2.0/24", "192.0.2.42", "10.20.30.40", true},
		{"mapped CIDR", "::ffff:192.0.2.0/120", "::ffff:192.0.2.42", "198.51.100.9", true},
		{"mapped CIDR plain IPv4", "::ffff:192.0.2.0/120", "192.0.2.42", "198.51.100.9", true},
		{"custom IPv6 zone", "2001:db8:109::/64", "2001:db8:109::42%eth0", "2001:db8:110::9", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix, err := UnmapPrefix(netip.MustParsePrefix(tc.prefix))
			if err != nil {
				t.Fatal(err)
			}
			n := &Normalizer{NATAddrs: []netip.Prefix{prefix}}
			if tc.configured {
				n.InternalNets = []netip.Prefix{prefix}
			}
			for _, pad := range padding {
				t.Run(fmt.Sprintf("padding_%q", pad), func(t *testing.T) {
					inside, outside := pad+tc.inside+pad, pad+tc.outside+pad
					if !n.IsInternal(inside) || n.IsInternal(outside) {
						t.Errorf("wrong internal classification: inside=%q outside=%q", inside, outside)
					}
					if !n.inPrefixes(n.NATAddrs, inside) || n.inPrefixes(n.NATAddrs, outside) {
						t.Errorf("wrong NAT classification: inside=%q outside=%q", inside, outside)
					}
					if n.inPrefixes(nil, inside) {
						t.Error("empty NAT configuration must not match")
					}
					for _, flow := range []struct{ src, dst, scope, postNAT string }{
						{inside, outside, "outbound", "1"},
						{outside, inside, "inbound", "1"},
						{inside, inside, "internal", "1"},
						{outside, outside, "external", ""},
					} {
						e := n.FromFlow(parse.Flow{SrcIP: flow.src, DstIP: flow.dst}, "netflow.fixture", "exporter.example")
						if e.Attrs["scope"] != flow.scope || e.Attrs["post_nat"] != flow.postNAT {
							t.Errorf("flow(%q, %q): scope=%q post_nat=%q, want %q/%q",
								flow.src, flow.dst, e.Attrs["scope"], e.Attrs["post_nat"], flow.scope, flow.postNAT)
						}
					}
				})
			}
		})
	}
}

func TestPR109AddressTrimmingDoesNotRepairInvalidAddresses(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	n := &Normalizer{InternalNets: prefixes, NATAddrs: prefixes}
	inputs := []string{
		"", " \t\v\u0085\u3000", "not-an-address",
		"192.0.\u00a02.42", "192.0.2.42:443", "192.0.2.42/32",
	}
	for _, r := range []rune{0, 0x001c, 0x007f, 0x00ad, 0x034f, 0x180e, 0x200b, 0x200c, 0x200d, 0x200e, 0x2060, 0xfeff} {
		if unicode.IsSpace(r) {
			t.Fatalf("fixture U+%04X must not be White_Space", r)
		}
		inputs = append(inputs, string(r)+"192.0.2.42", "192.0.2.42"+string(r))
	}
	for _, ip := range inputs {
		t.Run(fmt.Sprintf("address_%q", ip), func(t *testing.T) {
			if n.IsInternal(ip) || n.inPrefixes(n.NATAddrs, ip) {
				t.Errorf("invalid address %q must not match internal or NAT networks", ip)
			}
		})
	}
}
