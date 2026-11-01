package incidents

import (
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// The shipped fixture has Authentik and NetBird behind the same relay. PR88
// gives them separate incidents, so the affected source must also survive in
// the fields shown in the incident card and email. group_key is not projected
// by incidents_current, and Events is not persisted.
func TestPR88ClockSkewRelayIncidentsIdentifyAffectedSource(t *testing.T) {
	rule, fixture := pr80ClockSkewFixture(t)
	var events []*model.Event
	for _, event := range fixture {
		if event.Attrs["peer"] == "127.0.0.1" {
			events = append(events, event)
		}
	}
	if len(events) != 2 {
		t.Fatalf("want two shipped relay sources, got %d events", len(events))
	}
	created, _, _ := NewRegistry(0, nil).Apply(
		eval.Run([]*rules.Rule{rule}, events), events[0].Time().Add(time.Minute))
	if len(created) != 2 || created[0].GroupKey == created[1].GroupKey {
		t.Fatalf("different relay sources must have separate incidents: %+v", created)
	}
	for _, inc := range created {
		source := inc.Events[0].Attrs["source"]
		t.Run(source, func(t *testing.T) {
			// This is the persisted, operator-visible projection. A source
			// present only in the internal key or raw event is insufficient.
			visible := strings.Join([]string{
				inc.Summary(), inc.ActorName, inc.Node, inc.Note,
				strings.Join(inc.Sources, ", "), strings.Join(inc.Chain, "\n"),
				strings.Join(inc.Enrichment, "\n"),
			}, "\n")
			if !strings.Contains(visible, source) {
				t.Fatalf("incident %s hides affected source %q behind relay 127.0.0.1; group_key=%q is not shown in the card or email:\n%s",
					inc.IncidentID, source, inc.GroupKey, visible)
			}
		})
	}
}
