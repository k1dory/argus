package eval

import (
	"fmt"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

const silenceRule = `
title: silence
id: s-1
level: medium
detection:
  selection: {source.class: telemetry}
  threshold: {kind: absence, window: 10m, group_by: node}
  condition: selection and threshold
`

func tele(node string, ts, recv time.Time) *model.Event {
	return &model.Event{TS: model.FormatTS(ts), ReceivedAt: recv, SourceClass: "telemetry", Node: node, Action: "metric"}
}

// Состояние хранит событие с позднейшим временем источника, а не последнее
// принятое: задержанный лог не «омолаживает» и не «старит» группу.
func TestAbsenceStateKeepsLatestSourceTime(t *testing.T) {
	r := mkRule(t, silenceRule)
	other := mkRule(t, thresholdRule)
	rs := []*rules.Rule{r, other}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := NewAbsenceState(0)
	if !s.Observe(rs, tele("h1", now.Add(-20*time.Minute), now.Add(-20*time.Minute))) {
		t.Fatal("событие телеметрии подходит правилу молчания")
	}
	s.Observe(rs, tele("h1", now.Add(-12*time.Minute), now.Add(-12*time.Minute)))
	s.Observe(rs, tele("h1", now.Add(-30*time.Minute), now.Add(-time.Minute))) // задержанный
	if s.Observe(rs, smb(1, "svc", "10.0.0.1")) {
		t.Fatal("чужое событие не учитывается")
	}
	if s.Len() != 1 || s.last("s-1")["h1"].Time() != now.Add(-12*time.Minute) {
		t.Fatalf("последнее событие h1: %+v", s.last("s-1")["h1"])
	}
	dets, _ := Evaluate(Input{Rules: rs, Now: now, Absence: s})
	if len(dets) != 1 || dets[0].Key != "h1" || dets[0].Last != now.Add(-12*time.Minute) {
		t.Fatalf("молчание по состоянию без буфера: %+v", dets)
	}
	// буфер с более поздним событием группы перекрывает состояние
	dets, _ = Evaluate(Input{Rules: rs, Now: now, Absence: s, Events: []*model.Event{tele("h1", now.Add(-time.Minute), now.Add(-time.Minute))}})
	if len(dets) != 0 {
		t.Fatalf("узел говорит — сработки нет: %+v", dets)
	}
	// исключение «ложное» по узлу действует и на состояние
	dets, _ = Evaluate(Input{Rules: rs, Now: now, Absence: s, Exceptions: map[string][]Exception{"s-1": {{Field: "node", Value: "h1"}}}})
	if len(dets) != 0 {
		t.Fatalf("исключение по узлу: %+v", dets)
	}
}

// Prune: группы старше окна удерживания и правила, которых больше нет, уходят;
// потолок групп выбрасывает самые давно виденные (десятую часть сверх предела).
func TestAbsenceStatePruneAndCap(t *testing.T) {
	r := mkRule(t, silenceRule)
	rs := []*rules.Rule{r}
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	s := NewAbsenceState(10)
	for i := 0; i < 10; i++ {
		at := now.Add(time.Duration(i-20) * time.Minute)
		s.Observe(rs, tele(fmt.Sprintf("h%d", i), at, at))
	}
	if s.Len() != 10 {
		t.Fatalf("до потолка: %d", s.Len())
	}
	s.Observe(rs, tele("h-new", now, now))
	if s.Len() != 9 || s.last("s-1")["h0"] != nil || s.last("s-1")["h1"] != nil || s.last("s-1")["h-new"] == nil {
		t.Fatalf("сверх потолка уходят самые давние: len=%d %v", s.Len(), s.last("s-1"))
	}
	s.Prune(rs, now.Add(-15*time.Minute)) // уходят h2…h4 (−18…−16 мин)
	if s.Len() != 6 {
		t.Fatalf("по окну удерживания: %d", s.Len())
	}
	s.Prune(nil, now.Add(-time.Hour))
	if s.Len() != 0 || len(s.groups) != 0 {
		t.Fatalf("правило убрано из набора: %d", s.Len())
	}
	var nilState *AbsenceState
	if nilState.Len() != 0 || nilState.last("s-1") != nil {
		t.Fatal("nil-состояние пустое")
	}
	if NewAbsenceState(-1).max != DefaultAbsenceGroups || len(AbsenceRules([]*rules.Rule{r, mkRule(t, thresholdRule)})) != 1 {
		t.Fatal("умолчания")
	}
}

// Evaluate не переупорядочивает переданный срез.
func TestEvaluateKeepsInputOrder(t *testing.T) {
	r := mkRule(t, thresholdRule)
	in := []*model.Event{smb(5, "svc", "10.0.0.1"), smb(1, "svc", "10.0.0.2"), smb(3, "svc", "10.0.0.3")}
	before := []*model.Event{in[0], in[1], in[2]}
	dets, _ := Evaluate(Input{Rules: []*rules.Rule{r}, Events: in})
	for i := range in {
		if in[i] != before[i] {
			t.Fatal("входной срез переупорядочен")
		}
	}
	if len(dets) != 1 || dets[0].First.Second() != 1 {
		t.Fatalf("оценка всё равно по времени источника: %+v", dets)
	}
}
