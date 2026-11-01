package incidents

import (
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// group_by дополнили полями: открытый инцидент со старым ключом забирает только
// первая группа нового ключа с тем же началом; закрытый не подхватывается.
func TestRegistryAdoptsWidenedGroupKey(t *testing.T) {
	rule, fixture := pr80ClockSkewFixture(t)
	legacy := *rule
	legacy.Detection.GroupBy = "attrs.peer"
	first := fixture[0]
	now := first.Time().Add(time.Minute)
	old, _, _ := NewRegistry(0, nil).Apply(eval.Run([]*rules.Rule{&legacy}, []*model.Event{first}), now)
	if len(old) != 1 || old[0].GroupKey != first.Attrs["peer"] {
		t.Fatalf("фикстура: %+v", old)
	}
	other := *first
	other.Attrs = map[string]string{"peer": first.Attrs["peer"], "source": "nas.qnap", "transport": "internal"}
	for _, status := range []string{StatusNew, StatusClosed} {
		t.Run(status, func(t *testing.T) {
			persisted := *old[0]
			persisted.Events, persisted.Status = nil, status
			reg := NewRegistry(1, []Incident{persisted})
			created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{rule}, []*model.Event{first, &other}), now.Add(time.Minute))
			if status == StatusClosed {
				if len(created) != 2 {
					t.Fatalf("закрытый инцидент со старым ключом подхвачен: created=%d updated=%d", len(created), len(updated))
				}
				return
			}
			if len(created) != 1 || len(updated) != 1 || updated[0].IncidentID != persisted.IncidentID || created[0].GroupKey == updated[0].GroupKey {
				t.Fatalf("старый ключ — одной группе, второй источник — свой инцидент: created=%+v updated=%+v", created, updated)
			}
		})
	}
}
