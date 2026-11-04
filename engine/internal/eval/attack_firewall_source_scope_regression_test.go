package eval

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func pr76FirewallBurst(src, dst, scope string) []*model.Event {
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	var events []*model.Event
	for i := 0; i < 30; i++ {
		attrs := map[string]string{"prefix": "argus-drop-fwd"}
		if scope != "" {
			attrs["scope"] = scope
		}
		events = append(events, &model.Event{
			TS:     model.FormatTS(start.Add(time.Duration(i) * time.Second)),
			Source: "host.nftables", SourceClass: "firewall", Action: "net.firewall", Outcome: "deny",
			Node: "router", SrcIP: src, DstIP: dst, DstPort: uint16(2000 + i), Proto: "tcp", Attrs: attrs,
		})
	}
	return events
}

func pr76NoExternalScan(t *testing.T, r *rules.Rule, events []*model.Event) {
	t.Helper()
	for _, d := range Run([]*rules.Rule{r}, events) {
		if slices.Contains(d.Rule.Tags, "attack.t1595") {
			t.Fatalf("internal source %s is labeled as external Active Scanning: tags=%v events=%d",
				d.Key, d.Rule.Tags, len(d.Events))
		}
	}
}

// PR #76: свои публичные адреса остаются внутренними. INTERNAL_NETS уже
// задаёт эту границу у коллектора и в allowlist обратного канала движка.
func TestPR76FirewallRespectsConfiguredInternalNets(t *testing.T) {
	for _, tc := range []struct {
		name, nets, src, scope string
		wantExternal           bool
	}{
		{"own public block without scope", "192.168.0.0/20,185.25.9.0/24", "185.25.9.42", "", false},
		{"own public block with internal scope", "192.168.0.0/20,185.25.9.0/24", "185.25.9.42", "internal", false},
		{"same address outside configured nets", "192.168.0.0/20", "185.25.9.42", "", true},
		{"neighbor below own block", "192.168.0.0/20,185.25.9.0/24", "185.25.8.254", "", true},
		{"neighbor above own block", "192.168.0.0/20,185.25.9.0/24", "185.25.10.1", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("INTERNAL_NETS", tc.nets)
			r, err := rules.LoadFile("../../../rules/fw-inbound-deny-burst.yml")
			if err != nil {
				t.Fatal(err)
			}
			events := pr76FirewallBurst(tc.src, "185.25.9.57", tc.scope)
			if !tc.wantExternal {
				pr76NoExternalScan(t, r, events)
				return
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != 1 || dets[0].Key != tc.src || len(dets[0].Events) != 30 {
				t.Fatalf("external source %s attacking our public block must remain visible: %+v", tc.src, dets)
			}
		})
	}
}

// Адреса — строки в событиях и ClickHouse; ingestion их не канонизирует.
// Исключение должно зависеть от адреса, а не от регистра, сокращения IPv6
// или IPv4-mapped записи. 100.64/10 также входит в defaultInternalNets.
func TestPR76FirewallSpecialSourcesNotExternal(t *testing.T) {
	t.Setenv("INTERNAL_NETS", "")
	r, err := rules.LoadFile("../../../rules/fw-inbound-deny-burst.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{
		"10.10.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.5", "127.0.0.1", "169.254.1.5",
		"100.64.0.1", "100.127.255.254",
		"fc00::5", "fd12:3456::5", "fe80::5", "::1",
		"FC00::5", "FD12:3456::5", "FE80::5", "0:0:0:0:0:0:0:1",
		"::ffff:10.10.0.5", "::ffff:c0a8:105", "::FFFF:AC10:1",
	} {
		t.Run(src, func(t *testing.T) {
			if _, err := netip.ParseAddr(src); err != nil {
				t.Fatalf("regression fixture must be a valid address: %v", err)
			}
			pr76NoExternalScan(t, r, pr76FirewallBurst(src, "192.168.0.10", ""))
		})
	}
}

// Контроль отрицательных кейсов: исключения не должны поглощать внешние
// IPv4/IPv6-сканы, включая соседние с частными диапазоны и IPv4-mapped IP.
func TestPR76FirewallKeepsExternalScans(t *testing.T) {
	t.Setenv("INTERNAL_NETS", "192.168.0.0/20,185.25.9.0/24")
	r, err := rules.LoadFile("../../../rules/fw-inbound-deny-burst.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{
		"203.0.113.77", "198.51.100.76", "100.63.255.254", "100.128.0.1",
		"172.15.255.254", "172.32.0.1", "169.253.255.254", "169.255.0.1", "192.169.0.1",
		"2001:db8::77", "2001:DB8::77", "::ffff:203.0.113.77",
	} {
		t.Run(src, func(t *testing.T) {
			for _, dst := range []string{"192.168.0.10", "185.25.9.57"} {
				t.Run(dst, func(t *testing.T) {
					// Firewall-событие без attrs.scope тоже должно работать.
					events := pr76FirewallBurst(src, dst, "")
					if got := Run([]*rules.Rule{r}, events[:29]); len(got) != 0 {
						t.Fatalf("29 distinct ports must remain below threshold: %+v", got)
					}
					dets := Run([]*rules.Rule{r}, events)
					if len(dets) != 1 || dets[0].Key != src || len(dets[0].Events) != 30 {
						t.Fatalf("external scan %s -> %s lost grouping or evidence: %+v", src, dst, dets)
					}
					if !slices.Contains(dets[0].Rule.Tags, "attack.t1595") {
						t.Fatalf("external scan must retain Active Scanning: %v", dets[0].Rule.Tags)
					}
				})
			}
		})
	}
}
