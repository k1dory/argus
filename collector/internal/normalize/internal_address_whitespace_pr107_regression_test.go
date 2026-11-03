package normalize

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// /ingest/events decodes JSON and calls Event.Ensure before main assigns scope
// with FlowScope. Neither step currently removes padding from IP fields. The
// engine's field|internal accepts that padding, so scope must agree for the
// mapped prefixes and zoned addresses introduced in PR #107 as well.
func TestPR107InternalScopeMatchesEngineForPaddedAddresses(t *testing.T) {
	for _, tc := range []struct {
		name, cidr, inside, peer, outside string
	}{
		{"mapped CIDR", "::ffff:192.0.2.0/120", "::ffff:192.0.2.42", "192.0.2.7", "198.51.100.9"},
		{"default link-local zone", "", "fe80::42%eth0", "fe80::7", "2001:db8:108::9"},
		{"configured IPv6 zone", "2001:db8:107::/64", "2001:db8:107::42%eth0", "2001:db8:107::7", "2001:db8:108::9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &Normalizer{}
			if tc.cidr != "" {
				prefix, err := UnmapPrefix(netip.MustParsePrefix(tc.cidr))
				if err != nil {
					t.Fatal(err)
				}
				n.InternalNets = []netip.Prefix{prefix}
			}
			for _, padding := range []struct{ name, value string }{{"canonical control", ""}, {"padded NDJSON", " \t"}} {
				t.Run(padding.name, func(t *testing.T) {
					// Exercise the actual event decoding/defaulting contract, rather
					// than assuming a wire NetFlow decoder can produce padded IPs.
					body, err := json.Marshal(model.Event{
						Source: "fixture.normalized", Action: "event.dns", Outcome: "allow",
						SrcIP: padding.value + tc.inside + padding.value, DstIP: tc.outside,
						Attrs: map[string]string{"dns_query": "fixture.example"},
					})
					if err != nil {
						t.Fatal(err)
					}
					var event model.Event
					if err := json.Unmarshal(body, &event); err != nil {
						t.Fatal(err)
					}
					event.Ensure()
					if !n.IsInternal(event.SrcIP) {
						t.Errorf("INTERNAL_NETS=%q: own source %q is external; engine field|internal treats it as internal", tc.cidr, event.SrcIP)
					}
					for _, flow := range []struct{ src, dst, want string }{
						{event.SrcIP, event.DstIP, "outbound"},
						{event.DstIP, event.SrcIP, "inbound"},
						{event.SrcIP, tc.peer, "internal"},
						{tc.outside, padding.value + tc.outside + padding.value, "external"},
					} {
						if got := n.FlowScope(flow.src, flow.dst); got != flow.want {
							t.Errorf("scope(%q, %q)=%q, want %q", flow.src, flow.dst, got, flow.want)
						}
					}
				})
			}
		})
	}
}
