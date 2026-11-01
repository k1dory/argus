package eval

import (
	"slices"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Географическая аномалия должна оставаться видна, но пять успешных
// обращений к одной странице не свидетельствуют об Active Scanning.
// ATT&CK T1595: https://attack.mitre.org/techniques/T1595/
func TestForeignAccessGeographyDoesNotAssertActiveScanning(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/proxy-foreign-access.yml")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	var events []*model.Event
	for i := 0; i < 5; i++ {
		events = append(events, &model.Event{
			TS:     model.FormatTS(start.Add(time.Duration(i) * time.Minute)),
			Source: "proxy.nginx", SourceClass: "proxy", Action: "proxy.access", Outcome: "success",
			SrcIP: "198.51.100.76", DstIP: "10.20.0.10", DstPort: 443,
			Node: "proxy-01", Object: "/account", ActorName: "fixture-user",
			Attrs: map[string]string{"country": "DE", "method": "GET", "status": "200"},
		})
	}
	if got := Run([]*rules.Rule{r}, events[:4]); len(got) != 0 {
		t.Fatalf("four requests must remain below the geographic alert threshold: %+v", got)
	}
	dets := Run([]*rules.Rule{r}, events)
	if len(dets) != 1 || dets[0].Key != "198.51.100.76" || len(dets[0].Events) != 5 {
		t.Fatalf("the geographic signal must retain its grouping and evidence: %+v", dets)
	}
	if slices.Contains(dets[0].Rule.Tags, "attack.t1595") {
		t.Fatalf("five successful GETs to one page are tagged as Active Scanning without scanning evidence: %v", dets[0].Rule.Tags)
	}
}
