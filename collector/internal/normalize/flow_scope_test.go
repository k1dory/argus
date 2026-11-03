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
	if udp.Attrs["avg_pkt"] != "0" {
		t.Fatalf("avg_pkt без байт: %+v", udp.Attrs)
	}
	quic := n.FromFlow(parse.Flow{SrcIP: "192.168.13.14", DstIP: "172.235.1.1", DstPort: 53, Proto: 17, Packets: 3, Bytes: 3936}, "netflow.lan", "192.168.0.1")
	if quic.Attrs["avg_pkt"] != "1312" || quic.Attrs["post_nat"] != "" {
		t.Fatalf("avg_pkt: %+v", quic.Attrs)
	}
	nopk := n.FromFlow(parse.Flow{SrcIP: "192.168.13.14", DstIP: "172.235.1.1", DstPort: 53, Proto: 17}, "netflow.lan", "192.168.0.1")
	if _, ok := nopk.Attrs["avg_pkt"]; ok {
		t.Fatalf("avg_pkt без пакетов: %+v", nopk.Attrs)
	}
	n.NATAddrs = []netip.Prefix{netip.MustParsePrefix("185.25.9.57/32")}
	nat := n.FromFlow(parse.Flow{SrcIP: "185.25.9.57", DstIP: "172.235.1.1", DstPort: 53, Proto: 17, Packets: 3, Bytes: 3936}, "netflow.core", "185.25.9.1")
	if nat.Attrs["post_nat"] != "1" || nat.Attrs["scope"] != "outbound" {
		t.Fatalf("post_nat: %+v", nat.Attrs)
	}
	back := n.FromFlow(parse.Flow{SrcIP: "172.235.1.1", DstIP: "185.25.9.57", SrcPort: 53, Proto: 17, Packets: 1, Bytes: 1300}, "netflow.core", "185.25.9.1")
	if back.Attrs["post_nat"] != "1" {
		t.Fatalf("post_nat ответ: %+v", back.Attrs)
	}
	if parse.TCPFlagsString(0) != "" || parse.TCPFlagsString(0x11) != "AF" {
		t.Fatalf("flags string")
	}
}

// Те же сети, что у модификатора правил field|internal в движке: зона интерфейса
// не мешает, IPv4-mapped CIDR приводится к IPv4 (ревью #105).
func TestInternalZoneAndMappedPrefix(t *testing.T) {
	n := &Normalizer{}
	if !n.IsInternal("fe80::42%eth0") || n.FlowScope("fe80::42%eth0", "2001:db8::1") != "outbound" {
		t.Fatal("link-local с зоной — свой адрес")
	}
	p, err := UnmapPrefix(netip.MustParsePrefix("::ffff:192.0.2.0/120"))
	if err != nil || p != netip.MustParsePrefix("192.0.2.0/24") {
		t.Fatalf("mapped /120 → %v, %v", p, err)
	}
	if _, err := UnmapPrefix(netip.MustParsePrefix("::ffff:0:0/95")); err == nil {
		t.Fatal("IPv4-mapped короче /96 — ошибка")
	}
	if p, err := UnmapPrefix(netip.MustParsePrefix("2001:db8::/64")); err != nil || p.String() != "2001:db8::/64" {
		t.Fatalf("обычный IPv6 без изменений: %v, %v", p, err)
	}
	n.InternalNets = []netip.Prefix{p, mustUnmap(t, "::ffff:192.0.2.0/120"), mustUnmap(t, "2001:db8:105::/64")}
	for ip, want := range map[string]bool{"192.0.2.42": true, "::FFFF:C000:22A": true, "192.0.3.1": false, "2001:db8:105::42%eth0": true, "2001:db8:106::42%eth0": false} {
		if n.IsInternal(ip) != want {
			t.Errorf("%s: internal=%v, ожидалось %v", ip, !want, want)
		}
	}
	n.NATAddrs = []netip.Prefix{mustUnmap(t, "::ffff:185.25.9.57/128")}
	if nat := n.FromFlow(parse.Flow{SrcIP: "185.25.9.57", DstIP: "172.235.1.1", DstPort: 53, Proto: 17, Packets: 1}, "netflow.core", "185.25.9.1"); nat.Attrs["post_nat"] != "1" {
		t.Fatalf("NAT-адрес в IPv4-mapped записи: %+v", nat.Attrs)
	}
}

func mustUnmap(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := UnmapPrefix(netip.MustParsePrefix(s))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
