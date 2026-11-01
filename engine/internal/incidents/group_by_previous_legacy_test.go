package incidents

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// Строка до миграции 0039 (group_by пуст): по прежнему ключу подхватывается только
// инцидент, созданный раньше group_by_previous_before. Это случай INC-5312 на argus1:
// a41c-ops-067, ключ — только адрес, создан до слияния #88. Без границы — не
// подхватывается: пустой group_by не значит «до смены».
func TestPreviousGroupLegacyRowsNeedBoundary(t *testing.T) {
	rule, fixture := pr80ClockSkewFixture(t)
	if rule.GroupByPreviousBefore().IsZero() {
		t.Fatal("a41c-ops-067 должен задавать group_by_previous_before")
	}
	first := fixture[0]
	peer := first.Attrs["peer"]
	now := first.Time().Add(time.Minute)
	// То же правило без границы — через загрузчик (граница разбирается при загрузке).
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "rules", "ops", "collector-clock-skew.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, "group_by_previous_before:") {
			kept = append(kept, line)
		}
	}
	path := filepath.Join(t.TempDir(), "no-boundary.yml")
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	noBoundary, err := rules.LoadFile(path)
	if err != nil || !noBoundary.GroupByPreviousBefore().IsZero() || noBoundary.Detection.GroupByPrevious == "" {
		t.Fatalf("правило без границы: %v", err)
	}
	for _, tc := range []struct {
		name    string
		rule    *rules.Rule
		created string
		adopt   bool
	}{
		{"до границы (INC-5312)", rule, "2026-11-01 17:46:16", true},
		{"после границы", rule, "2026-11-01 18:30:00", false},
		{"граница не задана", noBoundary, "2026-11-01 17:46:16", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacy := Incident{
				IncidentID: "INC-5312", RuleID: rule.ID, Status: StatusNew, ActorName: first.ActorName, Node: first.Node,
				GroupKey: peer, CreatedAt: tc.created, UpdatedAt: tc.created, FirstTS: tc.created, LastTS: tc.created, EventCount: 1,
			}
			reg := NewRegistry(5312, []Incident{legacy})
			created, updated, _ := reg.Apply(eval.Run([]*rules.Rule{tc.rule}, []*model.Event{first}), now)
			if tc.adopt {
				if len(created) != 0 || len(updated) != 1 || updated[0].IncidentID != "INC-5312" ||
					updated[0].GroupKey != peer+"|"+first.Attrs["source"] || updated[0].GroupBy != rules.NormGroupBy(rule.GroupBy()) {
					t.Fatalf("строка до 0039 до границы должна продолжиться: created=%+v updated=%+v", created, updated)
				}
				return
			}
			if len(created) != 1 || len(updated) != 0 || created[0].IncidentID == "INC-5312" {
				t.Fatalf("подхвачен инцидент без доказательства, что он заведён до смены: created=%+v updated=%+v", created, updated)
			}
		})
	}
}
