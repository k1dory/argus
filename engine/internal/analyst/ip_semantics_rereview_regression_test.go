package analyst

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/enrich"
	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func TestPR64RereviewIPHostPseudonymsDoNotMergeAdjacentHosts(t *testing.T) {
	p := NewPseudonyms([]byte("pr64-rereview-ip"))
	// Independent HMAC-SHA256 calculation gives f6a4 for both four-character
	// host suffixes. The addresses are different hosts in the same /24.
	const first, second = "10.64.0.36", "10.64.0.155"
	a, b := p.IP(first), p.IP(second)
	if a == b {
		t.Errorf("two distinct hosts %s and %s collapse into the same state identity %q", first, second, a)
	}
}

func TestPR64RereviewURLIPRetainsAddressScopeAndNetwork(t *testing.T) {
	p := NewPseudonyms([]byte("pr64-rereview-url"))
	for _, tc := range []struct{ url, ip string }{
		{"https://10.64.12.34:8443/report.pdf", "10.64.12.34"},
		{"https://203.0.113.7:443/report.pdf", "203.0.113.7"},
		{"https://[fd12:3456:789a::1]/report.pdf", "fd12:3456:789a::1"},
		{"https://[fd12:3456:789a::1]:443/report.pdf", "fd12:3456:789a::1"},
	} {
		t.Run(tc.url, func(t *testing.T) {
			got := p.Detail(tc.url)
			if !strings.Contains(got, p.IP(tc.ip)) {
				t.Errorf("URL discarded the IP's scope/network/identity: %q, want address token %q", got, p.IP(tc.ip))
			}
		})
	}
}

type pr64RereviewIPSource struct{ event *model.Event }

func (s pr64RereviewIPSource) EventsAround(context.Context, string, string, string, string, time.Time, time.Time, int) ([]*model.Event, error) {
	return []*model.Event{s.event}, nil
}

func TestPR64RereviewIPv6DestinationKeepsItsPortAndIdentity(t *testing.T) {
	p := NewPseudonyms([]byte("pr64-rereview-ipv6"))
	for _, ip := range []string{"10.64.12.34", "fd12:3456:789a::1", "2001:db8::1"} {
		for _, enrichment := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enrichment=%t", ip, enrichment), func(t *testing.T) {
				now := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
				event := &model.Event{
					TS: model.FormatTS(now), Source: "ngfw.fixture", SourceClass: "ngfw",
					Action: "network.connect", Node: "web-01", ActorName: "root",
					SrcIP: "203.0.113.7", DstIP: ip, DstPort: 443,
				}
				rule := &rules.Rule{ID: "pr64-endpoint", Title: "Network connection", Level: "high"}
				created, _, _ := incidents.NewRegistry(64000, nil).Apply([]eval.Detection{{
					Rule: rule, Key: "root", Events: []*model.Event{event}, First: now, Last: now,
				}}, now)
				if len(created) != 1 {
					t.Fatal("fixture must create one incident")
				}
				inc := created[0]
				if enrichment {
					inc.Chain = nil
					inc.Enrichment = enrich.New(pr64RereviewIPSource{event}, "").Run(
						context.Background(), inc, []any{"ngfw.sessions"})
				}
				state := DecisionStateWith(inc, p)
				want := p.IP(ip) + ":443"
				if !strings.Contains(state, want) {
					t.Errorf("destination must remain %q; IPv6 port was interpreted as address bits:\n%s", want, state)
				}
			})
		}
	}
}
