package normalize

import (
	"net/netip"
	"testing"

	"github.com/devitex-soft/argus/collector/internal/parse"
)

func TestFlowScopeAndFlags(t *testing.T) {
	n := &Normalizer{}
	if got := n.FlowScope("203.0.113.9", "192.168.0.170"); got != "inbound" {
		t.Fatalf("inbound: %s", got)
	}
	if got := n.FlowScope("10.1.2.3", "8.8.8.8"); got != "outbound" {
		t.Fatalf("outbound: %s", got)
	}
	if got := n.FlowScope("10.1.2.3", "192.168.5.5"); got != "internal" {
		t.Fatalf("internal: %s", got)
	}
	if got := n.FlowScope("203.0.113.9", "198.51.100.7"); got != "external" {
		t.Fatalf("external: %s", got)
	}
	// Свой белый блок через InternalNets
	n.InternalNets = []netip.Prefix{netip.MustParsePrefix("185.25.9.0/24"), netip.MustParsePrefix("192.168.0.0/20")}
	if got := n.FlowScope("203.0.113.9", "185.25.9.57"); got != "inbound" {
		t.Fatalf("public own block inbound: %s", got)
	}
	if got := n.FlowScope("203.0.113.9", "10.1.2.3"); got != "external" {
		t.Fatalf("explicit nets replace defaults: %s", got)
	}

	syn := n.FromFlow(parse.Flow{SrcIP: "203.0.113.9", DstIP: "185.25.9.57", SrcPort: 4444, DstPort: 22, Proto: 6, TCPFlags: 0x02, Packets: 1, Bytes: 60}, "netflow.core", "185.25.9.1")
	if syn.Attrs["scope"] != "inbound" || syn.Attrs["tcp_flags"] != "S" || syn.Attrs["syn_only"] != "1" {
		t.Fatalf("syn flow attrs: %+v", syn.Attrs)
	}
	est := n.FromFlow(parse.Flow{SrcIP: "203.0.113.9", DstIP: "185.25.9.57", DstPort: 443, Proto: 6, TCPFlags: 0x1a, Packets: 20}, "netflow.core", "185.25.9.1")
	if est.Attrs["tcp_flags"] != "SAP" || est.Attrs["syn_only"] != "" {
		t.Fatalf("established flow attrs: %+v", est.Attrs)
	}
	udp := n.FromFlow(parse.Flow{SrcIP: "8.8.8.8", DstIP: "185.25.9.57", SrcPort: 53, DstPort: 40000, Proto: 17, Packets: 1}, "netflow.core", "185.25.9.1")
	if _, ok := udp.Attrs["tcp_flags"]; ok || udp.Attrs["syn_only"] != "" {
		t.Fatalf("udp flow attrs: %+v", udp.Attrs)
	}
	if parse.TCPFlagsString(0) != "" || parse.TCPFlagsString(0x11) != "AF" {
		t.Fatalf("flags string")
	}
}
