package eval

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Load the shipped rule, rather than a copy of its YAML. Each negative case
// has enough traffic to cross the threshold if its DNS guard is removed.
func TestDNSTunnelRequiresPositiveDNSRecords(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/dns-tunnel.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		count  int
		step   time.Duration
		change func(*model.Event, int)
		want   int
	}{
		{name: "40 named DNS records from NGFW", want: 1},
		{name: "39 records stay below threshold", count: 39},
		{name: "DNS action is case insensitive", change: func(e *model.Event, _ int) { e.Action = "DNS.Query" }, want: 1},
		{name: "resolver logs are eligible", change: func(e *model.Event, _ int) { e.Source, e.SourceClass = "dns.bind", "dns" }, want: 1},
		{name: "NGFW UDP 53 sessions with a domain", change: func(e *model.Event, _ int) {
			e.Action, e.Attrs["domain"] = "session.allow", "example.test"
			delete(e.Attrs, "dns_query")
		}},
		{name: "a query attribute cannot turn a session into DNS", change: func(e *model.Event, _ int) { e.Action = "session.allow" }},
		{name: "NetFlow UDP 53 is not a DNS record", change: func(e *model.Event, _ int) {
			e.Source, e.SourceClass, e.Action = "netflow.core", "netflow", "flow"
		}},
		{name: "NetFlow TCP 53 is not a DNS record", change: func(e *model.Event, _ int) {
			e.Source, e.SourceClass, e.Action, e.Proto = "netflow.core", "netflow", "flow", "tcp"
		}},
		{name: "DNS action without a name", change: func(e *model.Event, _ int) { delete(e.Attrs, "dns_query") }},
		{name: "DNS action with blank name", change: func(e *model.Event, _ int) { e.Attrs["dns_query"] = " \t\r\n" }},
		{name: "39 DNS records plus unrelated session", change: func(e *model.Event, i int) {
			if i == 39 {
				e.Action = "session.allow"
			}
		}},
		{name: "39 DNS records plus unnamed DNS record", change: func(e *model.Event, i int) {
			if i == 39 {
				delete(e.Attrs, "dns_query")
			}
		}},
		{name: "200 bytes is below size threshold", change: func(e *model.Event, _ int) { e.Bytes = 200 }},
		{name: "201 bytes crosses size threshold", change: func(e *model.Event, _ int) { e.Bytes = 201 }, want: 1},
		{name: "internal resolver traffic", change: func(e *model.Event, _ int) { e.Attrs["scope"] = "internal" }},
		{name: "inbound scans", change: func(e *model.Event, _ int) { e.Attrs["scope"] = "inbound" }},
		{name: "wrong destination port", change: func(e *model.Event, _ int) { e.DstPort = 5353 }},
		{name: "traffic outside the five minute window", step: 10 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			count, step := tc.count, tc.step
			if count == 0 {
				count = 40
			}
			if step == 0 {
				step = time.Second
			}
			var events []*model.Event
			start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
			for i := 0; i < count; i++ {
				e := &model.Event{TS: model.FormatTS(start.Add(time.Duration(i) * step)), Source: "ngfw.checkpoint", SourceClass: "ngfw",
					Action: "event.dns", SrcIP: "10.30.1.8", DstIP: "203.0.113.53", DstPort: 53, Proto: "udp", Bytes: 300,
					Attrs: map[string]string{"scope": "outbound", "dns_query": "encoded.example.test"}}
				if tc.change != nil {
					tc.change(e, i)
				}
				e.Ensure()
				events = append(events, e)
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != tc.want {
				t.Fatalf("detections=%d, want %d: %+v", len(dets), tc.want, dets)
			}
			if len(dets) > 0 && (dets[0].Key != "10.30.1.8" || len(dets[0].Events) != 40) {
				t.Fatalf("DNS grouping/evidence changed: %+v", dets[0])
			}
		})
	}
}

// The original positive fixture must stay effective when exclusions are
// strengthened; replay the supplied NGFW/NetFlow counterexamples beside it.
func TestDNSTunnelReferenceFixtures(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/dns-tunnel.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		fixture string
		want    int
	}{
		{"august.ndjson", 1},
		{"ngfw-port53-sessions.ndjson", 0},
		{"netflow-port53.ndjson", 0},
	} {
		t.Run(tc.fixture, func(t *testing.T) {
			f, err := os.Open("../../../fixtures/events/" + tc.fixture)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			var events []*model.Event
			scan := bufio.NewScanner(f)
			scan.Buffer(make([]byte, 4096), 1024*1024)
			for scan.Scan() {
				line := strings.TrimSpace(scan.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				var e model.Event
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					t.Fatal(err)
				}
				e.Ensure()
				events = append(events, &e)
			}
			if err := scan.Err(); err != nil {
				t.Fatal(err)
			}
			if len(events) == 0 {
				t.Fatal("empty regression fixture")
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != tc.want {
				t.Fatalf("detections=%d, want %d", len(dets), tc.want)
			}
			if len(dets) > 0 && (dets[0].Key != "10.30.1.8" || len(dets[0].Events) < 40) {
				t.Fatalf("positive fixture actor/evidence changed: %+v", dets[0])
			}
		})
	}
}
