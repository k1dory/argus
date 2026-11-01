package eval

import (
	"slices"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// T1595 описывает разведку до проникновения; скан с внутреннего узла —
// T1046 (Discovery). Общие firewall deny не устанавливают направление.
// https://attack.mitre.org/techniques/T1595/
// https://attack.mitre.org/techniques/T1046/
func TestFirewallInternalScanDoesNotAssertExternalReconnaissance(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/fw-inbound-deny-burst.yml")
	if err != nil {
		t.Fatal(err)
	}
	eventsFor := func(srcIP, ingress string) []*model.Event {
		start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
		var events []*model.Event
		for i := 0; i < 30; i++ {
			events = append(events, &model.Event{
				TS:     model.FormatTS(start.Add(time.Duration(i) * time.Second)),
				Source: "host.nftables", SourceClass: "firewall", Action: "net.firewall", Outcome: "deny",
				Node: "router", SrcIP: srcIP, DstIP: "10.20.0.10", DstPort: uint16(2000 + i), Proto: "tcp",
				Attrs: map[string]string{"prefix": "argus-drop-fwd", "in": ingress},
			})
		}
		return events
	}
	// Контроль: правило продолжает замечать настоящий входящий скан.
	external := Run([]*rules.Rule{r}, eventsFor("203.0.113.77", "wan0"))
	if len(external) != 1 || len(external[0].Events) != 30 {
		t.Fatalf("the inbound scan must retain its detection and evidence: %+v", external)
	}
	// Тот же поток deny от скомпрометированного внутреннего узла. Допустимо
	// отдельное правило Discovery либо исключение из inbound-правила, но не T1595.
	for _, d := range Run([]*rules.Rule{r}, eventsFor("10.10.0.5", "lan0")) {
		if slices.Contains(d.Rule.Tags, "attack.t1595") {
			t.Fatalf("internal service discovery is mislabeled as external Active Scanning: source=%s tags=%v", d.Key, d.Rule.Tags)
		}
	}
}
