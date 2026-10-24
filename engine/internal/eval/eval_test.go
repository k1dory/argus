package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/rules"
)

func mkRule(t *testing.T, yml string) *rules.Rule {
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

func smb(sec int, actor, dst string) *model.Event {
	e := &model.Event{TS: fmt.Sprintf("2026-08-14 03:12:%02d.000", sec), Action: "session.allow", DstPort: 445,
		ActorName: actor, ActorKind: "service", DstIP: dst, Source: "ngfw.checkpoint"}
	e.Ensure()
	return e
}

const thresholdRule = `
title: t
id: t-1
level: critical
detection:
  selection: {event.action: session.allow, dst.port: 445, actor.kind: service}
  threshold: {field: dst.ip, distinct: 3, window: 1m, group_by: actor.name}
  condition: selection and threshold
`

func TestThresholdFiresOncePerWindowAndCollectsTail(t *testing.T) {
	r := mkRule(t, thresholdRule)
	var evs []*model.Event
	for i := 0; i < 5; i++ {
		evs = append(evs, smb(i*5, "svc", fmt.Sprintf("10.0.0.%d", i)))
	}
	evs = append(evs, smb(10, "svc", "10.0.0.1")) // повтор адреса — не новый distinct
	evs = append(evs, smb(20, "user1", "10.0.0.9"))
	dets := Run([]*rules.Rule{r}, evs)
	if len(dets) != 1 {
		t.Fatalf("сработок %d, ожидалась 1", len(dets))
	}
	if dets[0].Key != "svc" || len(dets[0].Events) != 6 {
		t.Fatalf("key=%s events=%d", dets[0].Key, len(dets[0].Events))
	}
}

func TestThresholdWindowSlidesAndRefires(t *testing.T) {
	r := mkRule(t, thresholdRule)
	var evs []*model.Event
	for i := 0; i < 3; i++ {
		evs = append(evs, smb(i, "svc", fmt.Sprintf("10.0.0.%d", i)))
	}
	// через 2 минуты новая волна — окно 1m сдвинулось, должна быть вторая сработка
	for i := 0; i < 3; i++ {
		e := smb(i, "svc", fmt.Sprintf("10.0.1.%d", i))
		e.TS = fmt.Sprintf("2026-08-14 03:15:%02d.000", i)
		evs = append(evs, e)
	}
	dets := Run([]*rules.Rule{r}, evs)
	if len(dets) != 2 {
		t.Fatalf("сработок %d, ожидалось 2", len(dets))
	}
}

func TestSelectionOnlyDedupes(t *testing.T) {
	r := mkRule(t, `
title: s
id: s-1
level: high
dedupe: 10m
detection:
  selection: {source.class: edr, attrs.name|contains: lsass}
  condition: selection
`)
	mk := func(sec int, node string) *model.Event {
		e := &model.Event{TS: fmt.Sprintf("2026-08-14 03:44:%02d.000", sec), SourceClass: "edr", Node: node, ActorName: node,
			Attrs: map[string]string{"name": "Suspicious LSASS access"}}
		e.Ensure()
		return e
	}
	dets := Run([]*rules.Rule{r}, []*model.Event{mk(1, "wks-1"), mk(2, "wks-1"), mk(3, "wks-2")})
	if len(dets) != 2 {
		t.Fatalf("сработок %d, ожидалось 2 (по узлам)", len(dets))
	}
	if len(dets[0].Events) != 2 {
		t.Fatalf("склейка: %d", len(dets[0].Events))
	}
}

func TestFilterExcludes(t *testing.T) {
	r := mkRule(t, `
title: f
id: f-1
level: high
detection:
  selection: {dst.port: 53, bytes: '> 200'}
  filter: {dst.ip: [10.0.0.53]}
  threshold: {count: 3, window: 5m, group_by: src.ip}
  condition: selection and not filter and threshold
`)
	mk := func(i int, dst string) *model.Event {
		e := &model.Event{TS: fmt.Sprintf("2026-08-14 05:20:%02d.000", i), DstPort: 53, Bytes: 300, SrcIP: "10.30.1.8", DstIP: dst}
		e.Ensure()
		return e
	}
	evs := []*model.Event{mk(1, "10.0.0.53"), mk(2, "10.0.0.53"), mk(3, "10.0.0.53"), mk(4, "91.108.4.1"), mk(5, "91.108.4.1")}
	if dets := Run([]*rules.Rule{r}, evs); len(dets) != 0 {
		t.Fatalf("свои резолверы должны отсекаться, сработок %d", len(dets))
	}
	evs = append(evs, mk(6, "91.108.4.1"))
	if dets := Run([]*rules.Rule{r}, evs); len(dets) != 1 {
		t.Fatalf("три внешних запроса → 1 сработка, получено %d", len(dets))
	}
}

func TestAbsenceFiresRelativeToNow(t *testing.T) {
	r := mkRule(t, `
title: silence
id: abs-1
level: medium
detection:
  selection: {source.class: wazuh}
  threshold: {kind: absence, window: 15m, group_by: node}
  condition: selection and threshold
`)
	mk := func(sec int, node string) *model.Event {
		e := &model.Event{TS: fmt.Sprintf("2026-08-14 05:00:%02d.000", sec), SourceClass: "wazuh", Node: node}
		e.Ensure()
		return e
	}
	evs := []*model.Event{mk(1, "app-01"), mk(5, "app-02")}
	base := evs[1].Time()
	dets, _ := Evaluate(Input{Rules: []*rules.Rule{r}, Events: evs, Now: base.Add(10 * time.Minute)})
	if len(dets) != 0 {
		t.Fatalf("10 минут тишины < 15m — не должно срабатывать, получено %d", len(dets))
	}
	dets, _ = Evaluate(Input{Rules: []*rules.Rule{r}, Events: evs, Now: base.Add(20 * time.Minute)})
	if len(dets) != 2 || dets[0].Reason == "" {
		t.Fatalf("оба узла молчат > 15m: %d %+v", len(dets), dets)
	}
}

func TestPeriodicNeedsRegularIntervals(t *testing.T) {
	r := mkRule(t, `
title: beacon
id: per-1
level: low
detection:
  selection: {source.class: netflow}
  threshold: {kind: periodic, count: 5, window: 1h, group_by: src.ip, jitter: 0.05}
  condition: selection and threshold
`)
	mk := func(sec int, src string) *model.Event {
		e := &model.Event{TS: time.Date(2026, 8, 14, 7, 0, 0, 0, time.UTC).Add(time.Duration(sec) * time.Second).Format("2006-01-02 15:04:05.000"),
			SourceClass: "netflow", SrcIP: src, DstIP: "91.1.1.1"}
		e.Ensure()
		return e
	}
	var evs []*model.Event
	for i, j := range []int{0, 2, -1, 3, -2, 1} { // 300 с ± 3
		evs = append(evs, mk(i*300+j, "10.0.0.1"))
	}
	for i, j := range []int{0, 90, -40, 120, -70, 30} { // тот же средний интервал, но рваный
		evs = append(evs, mk(i*300+j, "10.0.0.2"))
	}
	dets := Run([]*rules.Rule{r}, evs)
	if len(dets) != 1 || dets[0].Key != "10.0.0.1" {
		t.Fatalf("только ровный маячок: %+v", dets)
	}
}

func TestExceptionsAndClosers(t *testing.T) {
	r := mkRule(t, `
title: ci
id: ci-1
level: high
detection:
  selection: {source.class: cicd, attrs.log|contains: token}
  condition: selection
close_on:
  source.class: cicd
  event.action|contains: token_rotated
`)
	mk := func(sec int, actor, action, log string) *model.Event {
		e := &model.Event{TS: fmt.Sprintf("2026-08-14 04:01:%02d.000", sec), SourceClass: "cicd", ActorName: actor, Action: action, Attrs: map[string]string{"log": log}}
		e.Ensure()
		return e
	}
	evs := []*model.Event{mk(1, "bot", "gitlab.build.success", "TOKEN=abc"), mk(2, "human", "gitlab.build.success", "TOKEN=def"), mk(30, "bot", "gitlab.project_access_token_rotated", "")}
	dets, closers := Evaluate(Input{Rules: []*rules.Rule{r}, Events: evs,
		Exceptions: map[string][]Exception{"ci-1": {{Field: "actor.name", Value: "human"}}}})
	if len(dets) != 1 || dets[0].Key != "bot" {
		t.Fatalf("исключение по actor.name=human должно убрать вторую сработку: %+v", dets)
	}
	if len(closers) != 1 || closers[0].Key != "bot" {
		t.Fatalf("closer по ротации токена: %+v", closers)
	}
}
