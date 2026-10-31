package eval

import (
	"sort"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

// AbsenceState — последнее событие каждой группы правил «молчание» (threshold
// kind: absence), отдельно от буфера кандидатов. Буфер ограничен по числу
// (ENGINE_BUFFER_MAX) и при шторме NetFlow выбрасывает старые события — вместе
// с последним событием телеметрии узла, после чего правило переставало видеть
// узел и молчание не замечалось. Здесь хранится по одному событию на (правило,
// группу), обновляется каждым подходящим событием потока до чистки буфера.
//
// Память ограничена числом групп (max): сверх него выбрасывается десятая часть
// групп с самым давним последним событием. Возраст ограничен Prune — тем же
// окном, что и буфер (retention), так что молчание видно ровно столько, сколько
// раньше было видно по буферу без потолка по числу.
type AbsenceState struct {
	max    int
	groups map[string]map[string]*model.Event // rule_id → ключ группы → последнее событие
	n      int
}

// DefaultAbsenceGroups — потолок групп по умолчанию: узлы и агенты парка, а не
// адреса потоков, поэтому сто тысяч — с большим запасом (около 100 МБ в худшем случае).
const DefaultAbsenceGroups = 100_000

// NewAbsenceState — пустое состояние с потолком max групп (≤ 0 — DefaultAbsenceGroups).
func NewAbsenceState(max int) *AbsenceState {
	if max <= 0 {
		max = DefaultAbsenceGroups
	}
	return &AbsenceState{max: max, groups: map[string]map[string]*model.Event{}}
}

// AbsenceRules — правила «молчание» из набора.
func AbsenceRules(rs []*rules.Rule) []*rules.Rule {
	var out []*rules.Rule
	for _, r := range rs {
		if r.IsAbsence() {
			out = append(out, r)
		}
	}
	return out
}

// Observe учитывает событие для правил молчания из rs (не-absence пропускаются):
// для группы запоминается событие с самым поздним временем источника — как
// последнее событие окна в runRule. Возвращает true, если событие подошло хоть
// одному правилу.
func (s *AbsenceState) Observe(rs []*rules.Rule, e *model.Event) bool {
	matched := false
	for _, r := range rs {
		if !r.IsAbsence() || !r.Match(e) {
			continue
		}
		matched = true
		key := groupKey(rules.Getter(r.GroupBy()), e)
		g := s.groups[r.ID]
		if g == nil {
			g = map[string]*model.Event{}
			s.groups[r.ID] = g
		}
		prev, ok := g[key]
		if !ok {
			s.n++
		}
		if !ok || !e.Time().Before(prev.Time()) {
			g[key] = e
		}
	}
	if s.n > s.max {
		s.evictOldest(s.n - s.max + s.max/10)
	}
	return matched
}

// seenAt — время, по которому группа стареет: приём, без него — время источника.
func seenAt(e *model.Event) time.Time {
	if !e.ReceivedAt.IsZero() {
		return e.ReceivedAt
	}
	return e.Time()
}

func (s *AbsenceState) evictOldest(k int) {
	type ref struct {
		rule, key string
		at        time.Time
	}
	all := make([]ref, 0, s.n)
	for rule, g := range s.groups {
		for key, e := range g {
			all = append(all, ref{rule, key, seenAt(e)})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].at.Before(all[j].at) })
	for i := 0; i < k && i < len(all); i++ {
		delete(s.groups[all[i].rule], all[i].key)
		s.n--
	}
}

// Prune убирает группы, чьё последнее событие принято раньше cut, и правила,
// которых больше нет среди rs (перечитаны правила).
func (s *AbsenceState) Prune(rs []*rules.Rule, cut time.Time) {
	live := map[string]bool{}
	for _, r := range rs {
		if r.IsAbsence() {
			live[r.ID] = true
		}
	}
	for rule, g := range s.groups {
		if !live[rule] {
			s.n -= len(g)
			delete(s.groups, rule)
			continue
		}
		for key, e := range g {
			if seenAt(e).Before(cut) {
				delete(g, key)
				s.n--
			}
		}
	}
}

// Len — число групп во всех правилах молчания.
func (s *AbsenceState) Len() int {
	if s == nil {
		return 0
	}
	return s.n
}

// last — последние события групп правила (ключ → событие); nil-состояние — пусто.
func (s *AbsenceState) last(ruleID string) map[string]*model.Event {
	if s == nil {
		return nil
	}
	return s.groups[ruleID]
}
