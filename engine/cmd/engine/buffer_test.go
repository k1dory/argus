package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/eval"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func TestTrimBufferByAgeAndCap(t *testing.T) {
	now := time.Now()
	var buf []*model.Event
	for i := 0; i < 10; i++ {
		buf = append(buf, &model.Event{Action: "x", ReceivedAt: now.Add(time.Duration(i-10) * time.Minute)})
	}
	buf = append(buf, &model.Event{Action: "no-ts"})
	kept, evicted := trimBuffer(buf, now.Add(-5*time.Minute), 0)
	if evicted != 0 || len(kept) != 6 {
		t.Fatalf("по возрасту: kept=%d evicted=%d, ожидалось 6/0", len(kept), evicted)
	}
	kept, evicted = trimBuffer(kept, time.Time{}, 4)
	if evicted != 2 || len(kept) != 4 {
		t.Fatalf("по потолку: kept=%d evicted=%d, ожидалось 4/2", len(kept), evicted)
	}
	if kept[0].ReceivedAt.Before(now.Add(-3*time.Minute)) || kept[len(kept)-1].Action != "no-ts" {
		t.Fatalf("выброшены не самые старые: первый %v, последний %q", kept[0].ReceivedAt, kept[len(kept)-1].Action)
	}
	if kept, evicted = trimBuffer(nil, now, 1); len(kept) != 0 || evicted != 0 {
		t.Fatalf("пустой буфер: kept=%d evicted=%d", len(kept), evicted)
	}
}

func TestRetentionCappedByLookback(t *testing.T) {
	e := &engine{lookback: time.Hour}
	e.rules.Store(&[]*rules.Rule{})
	if got := e.retention(30 * time.Second); got != 16*time.Minute {
		t.Fatalf("без правил: %v, ожидалось 15m + 2×30s", got)
	}
	e.lookback = 10 * time.Minute
	if got := e.retention(30 * time.Second); got != 11*time.Minute {
		t.Fatalf("потолок: %v, ожидалось 10m + 1m", got)
	}
}

func loadTestRule(t *testing.T, yml string) *rules.Rule {
	t.Helper()
	p := filepath.Join(t.TempDir(), "r.yml")
	if err := os.WriteFile(p, []byte(yml), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := rules.LoadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const hostSilenceYML = `title: host silence
id: t-host-silence
level: medium
detection:
  selection:
    source.class: telemetry
  threshold:
    kind: absence
    window: 10m
    group_by: node
  condition: selection and threshold
`

const netflowCountYML = `title: flows
id: t-flows
level: low
detection:
  selection:
    source.class: netflow
  threshold:
    count: 1000000
    window: 1h
    group_by: src.ip
  condition: selection and threshold
`

func silenceFired(dets []eval.Detection, node string) bool {
	for _, d := range dets {
		if d.Rule.ID == "t-host-silence" && d.Key == node {
			return true
		}
	}
	return false
}

// Сценарий отчёта: NetFlow-кандидаты переполняют буфер (ENGINE_BUFFER_MAX),
// последнее событие телеметрии узла вытесняется — по одному буферу правило
// молчания узел больше не видит. С отдельным состоянием молчания сработка есть.
func TestHostSilenceSurvivesBufferEviction(t *testing.T) {
	rs := []*rules.Rule{loadTestRule(t, hostSilenceYML), loadTestRule(t, netflowCountYML)}
	now := time.Now().UTC().Truncate(time.Second)
	t0 := now.Add(-15 * time.Minute)
	e := &engine{bufferMax: 100, absence: eval.NewAbsenceState(0)}
	e.rules.Store(&rs)
	ctx := context.Background()
	tele := &model.Event{TS: model.FormatTS(t0), ReceivedAt: t0, Source: "telemetry.h1", SourceClass: "telemetry", Node: "h1", Action: "metric"}
	var buffer []*model.Event
	buffer, _ = e.ingest(ctx, rs, []*model.Event{tele}, buffer)
	evicted := 0
	for page := 0; page < 10; page++ {
		var evs []*model.Event
		for i := 0; i < 100; i++ {
			at := t0.Add(time.Duration(page*100+i+1) * 100 * time.Millisecond).Truncate(time.Second)
			evs = append(evs, &model.Event{TS: model.FormatTS(at), ReceivedAt: at, Source: "netflow.core", SourceClass: "netflow", Action: "flow", SrcIP: "10.0.0.1"})
		}
		var n int
		buffer, n = e.ingest(ctx, rs, evs, buffer)
		evicted += n
	}
	var n int
	buffer, n = trimBuffer(buffer, now.Add(-e.retention(30*time.Second)), e.bufferMax)
	evicted += n
	for _, ev := range buffer {
		if ev == tele {
			t.Fatal("событие телеметрии не должно жить в буфере: правило молчания берёт его из состояния")
		}
	}
	if evicted == 0 || len(buffer) != e.bufferMax {
		t.Fatalf("буфер должен упереться в потолок: len=%d evicted=%d", len(buffer), evicted)
	}
	// Без состояния (как до исправления) молчание узла не видно.
	dets, _ := eval.Evaluate(eval.Input{Rules: rs, Events: buffer, Now: now})
	if silenceFired(dets, "h1") {
		t.Fatal("контроль: без события телеметрии в буфере правило не срабатывает")
	}
	dets, _ = eval.Evaluate(eval.Input{Rules: rs, Events: buffer, Now: now, Absence: e.absence})
	if !silenceFired(dets, "h1") {
		t.Fatalf("молчание h1 после вытеснения буфера должно сработать: %+v", dets)
	}
	// Узел заговорил — молчания нет; группа стареет вместе с буфером (retention).
	back := &model.Event{TS: model.FormatTS(now.Add(-time.Minute)), ReceivedAt: now.Add(-time.Minute), SourceClass: "telemetry", Node: "h1"}
	buffer, _ = e.ingest(ctx, rs, []*model.Event{back}, buffer)
	if dets, _ = eval.Evaluate(eval.Input{Rules: rs, Events: buffer, Now: now, Absence: e.absence}); silenceFired(dets, "h1") {
		t.Fatal("узел заговорил — сработки нет")
	}
	e.absence.Prune(rs, now)
	if e.absence.Len() != 0 {
		t.Fatalf("группы старше окна удерживания убираются: %d", e.absence.Len())
	}
}

// Буфер хранится в порядке приёма, правила оцениваются по времени источника:
// оценка не переупорядочивает буфер, и чистка по потолку выбрасывает давно
// принятые события, а задержанный лог свежего приёма остаётся.
func TestTrimBufferKeepsFreshReceiptsAfterEvaluate(t *testing.T) {
	rs := []*rules.Rule{loadTestRule(t, netflowCountYML)}
	now := time.Now().UTC().Truncate(time.Second)
	var buffer []*model.Event
	for i := 0; i < 5; i++ {
		at := now.Add(time.Duration(i-10) * time.Minute)
		buffer = append(buffer, &model.Event{TS: model.FormatTS(at), ReceivedAt: at, SourceClass: "netflow", Action: fmt.Sprintf("r%d", i)})
	}
	// задержанный лог: время источника — час назад, принят только что
	buffer = append(buffer, &model.Event{TS: model.FormatTS(now.Add(-time.Hour)), ReceivedAt: now, SourceClass: "netflow", Action: "delayed"})
	eval.Evaluate(eval.Input{Rules: rs, Events: buffer, Now: now})
	if buffer[len(buffer)-1].Action != "delayed" {
		t.Fatal("оценка не должна менять порядок буфера")
	}
	kept, evicted := trimBuffer(buffer, time.Time{}, 3)
	if evicted != 3 || len(kept) != 3 || kept[2].Action != "delayed" || kept[0].Action != "r3" {
		t.Fatalf("остались не самые свежие по приёму: %v", actions(kept))
	}
	// буфер, переупорядоченный по ts (как делала старая оценка на месте), чистится так же
	shuffled := []*model.Event{
		{ReceivedAt: now, Action: "delayed"},
		{ReceivedAt: now.Add(-3 * time.Minute), Action: "a"},
		{ReceivedAt: now.Add(-2 * time.Minute), Action: "b"},
		{Action: "no-ts"},
	}
	kept, _ = trimBuffer(shuffled, time.Time{}, 2)
	if got := actions(kept); got != "delayed,no-ts" {
		t.Fatalf("по приёму, без времени приёма — как самые свежие: %s", got)
	}
}

func actions(evs []*model.Event) string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return strings.Join(out, ",")
}

// Источник может прислать старое событие сейчас или событие с часами в будущем
// давно. Ни source ts, ни позиция в срезе не определяют срок жизни в памяти.
func TestTrimBufferAgeUsesReceiptTime(t *testing.T) {
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	cut := now.Add(-10 * time.Minute)
	delayed := &model.Event{Action: "delayed", TS: model.FormatTS(now.Add(-24 * time.Hour)), ReceivedAt: now}
	old := &model.Event{Action: "future-clock", TS: model.FormatTS(now.Add(time.Hour)), ReceivedAt: cut.Add(-time.Second)}
	boundary := &model.Event{Action: "boundary", TS: model.FormatTS(now), ReceivedAt: cut}
	missing := &model.Event{Action: "no-receipt", TS: model.FormatTS(now.Add(-24 * time.Hour))}
	for _, input := range [][]*model.Event{
		{delayed, old, boundary, missing},
		{old, missing, boundary, delayed},
	} {
		kept, evicted := trimBuffer(input, cut, 0)
		got := map[*model.Event]bool{}
		for _, e := range kept {
			got[e] = true
		}
		if evicted != 0 || len(kept) != 3 || got[old] || !got[delayed] || !got[boundary] || !got[missing] {
			t.Fatalf("возраст по received_at, граничная секунда включительно: kept=%s cap-evicted=%d", actions(kept), evicted)
		}
	}
}

// Событие молчания может одновременно быть кандидатом другого правила.
// Переполнение общего буфера и поздний старый лог не должны ни забыть тихий
// узел, ни сделать говорящий узел тихим, ни придумать ранее неизвестный узел.
func TestHostSilenceSurvivesMixedCandidatesAndDelayedReceipt(t *testing.T) {
	telemetryCount := strings.ReplaceAll(netflowCountYML, "source.class: netflow", "source.class: telemetry")
	telemetryCount = strings.ReplaceAll(telemetryCount, "id: t-flows", "id: t-telemetry")
	rs := []*rules.Rule{loadTestRule(t, hostSilenceYML), loadTestRule(t, netflowCountYML), loadTestRule(t, telemetryCount)}
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	e := &engine{bufferMax: 4, absence: eval.NewAbsenceState(0)}
	event := func(node string, ts, recv time.Time) *model.Event {
		return &model.Event{Node: node, SourceClass: "telemetry", TS: model.FormatTS(ts), ReceivedAt: recv}
	}
	quiet := event("quiet", now.Add(-15*time.Minute), now.Add(-15*time.Minute))
	active := event("active", now.Add(-time.Minute), now.Add(-time.Minute))
	buffer, _ := e.ingest(context.Background(), rs, []*model.Event{quiet, active}, nil)
	if len(buffer) != 2 {
		t.Fatal("контроль: телеметрия должна попасть и в общий буфер кандидатов")
	}
	for page := 0; page < 3; page++ {
		var flows []*model.Event
		for i := 0; i < 10; i++ {
			flows = append(flows, &model.Event{SourceClass: "netflow", TS: model.FormatTS(now), ReceivedAt: now, SrcIP: "10.0.0.1"})
		}
		buffer, _ = e.ingest(context.Background(), rs, flows, buffer)
	}
	for _, ev := range buffer {
		if ev == quiet || ev == active {
			t.Fatal("контроль: исходная телеметрия должна быть вытеснена")
		}
	}
	late := event("quiet", now.Add(-24*time.Hour), now)
	buffer, _ = e.ingest(context.Background(), rs, []*model.Event{late}, buffer)
	detections, _ := eval.Evaluate(eval.Input{Rules: rs, Events: buffer, Absence: e.absence, Now: now})
	if !silenceFired(detections, "quiet") || silenceFired(detections, "active") || len(detections) != 1 || e.absence.Len() != 2 {
		t.Fatalf("только ранее наблюдавшийся тихий узел должен сработать: groups=%d detections=%+v", e.absence.Len(), detections)
	}
}
