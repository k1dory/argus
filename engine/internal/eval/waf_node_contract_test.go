package eval

import (
	"fmt"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Keep the actual autoblock rule aligned with the collector's node contract:
// client Host variations cannot replace three distinct trusted WAF nodes.
func TestWAFScannerCountsTrustedNodesOnly(t *testing.T) {
	r, err := rules.LoadFile("../../../rules/waf-scanner-multihost.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		nodes []string
		want  int
	}{
		{"one node, three client hosts", []string{"10.0.10.11", "10.0.10.11", "10.0.10.11"}, 0},
		{"two trusted nodes", []string{"10.0.10.11", "10.0.10.12", "10.0.10.11"}, 0},
		{"three trusted nodes", []string{"10.0.10.11", "10.0.10.12", "10.0.10.13"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events []*model.Event
			for i, node := range tc.nodes {
				e := &model.Event{TS: fmt.Sprintf("2026-10-30 12:00:%02d.000", i), Node: node,
					Source: "waf.modsecurity", SourceClass: "waf", Action: "http.attack", SrcIP: "198.51.100.77",
					Attrs: map[string]string{"host": fmt.Sprintf("203.0.113.%d", i+11), "http_host": fmt.Sprintf("203.0.113.%d", i+11)}}
				e.Ensure()
				events = append(events, e)
			}
			dets := Run([]*rules.Rule{r}, events)
			if len(dets) != tc.want {
				t.Fatalf("detections=%d, want %d: %+v", len(dets), tc.want, dets)
			}
			if len(dets) > 0 && (dets[0].Key != "198.51.100.77" || len(dets[0].Events) != 3) {
				t.Fatalf("scanner grouping/evidence changed: %+v", dets[0])
			}
		})
	}
}
