package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/devitex-soft/argus/engine/internal/analyst"
	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
)

const diskRule = `
title: disk
id: t-disk
level: high
detection:
  selection: {source.class: telemetry, action: disk.usage, value: '>= 90'}
  reset: {source.class: telemetry, action: disk.usage, value: '< 90'}
  threshold: {kind: consecutive, count: 3, window: 15m, group_by: node}
  condition: selection and threshold
close_on: {source.class: telemetry, action: disk.usage, value: '< 85'}
`

func diskEv(ts string, v float64) *model.Event {
	e := &model.Event{TS: ts, Source: "telemetry.node", SourceClass: "telemetry", Action: "disk.usage", Node: "db-01", Value: v, Unit: "percent"}
	e.Ensure()
	return e
}

func lastIncident(t *testing.T, f *fakeCH) incidents.Incident {
	t.Helper()
	rows := f.rows("incidents")
	if len(rows) == 0 {
		t.Fatal("инцидентов нет")
	}
	var inc incidents.Incident
	if err := json.Unmarshal([]byte(rows[len(rows)-1]), &inc); err != nil {
		t.Fatal(err)
	}
	return inc
}

// Регрессия: буфер 80 → 91 → 93 → 95 заводит инцидент и НЕ закрывает его
// старым нормальным замером; восстановление позже последнего нарушения закрывает.
func TestCycleCloseOnRequiresRecoveryAfterViolation(t *testing.T) {
	f := newFakeCH(t)
	e := testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": diskRule}), respond.Config{}, "s", "s")
	rs := e.current()
	buf := []*model.Event{diskEv("2026-10-20 10:00:00.000", 80), diskEv("2026-10-20 10:05:00.000", 91), diskEv("2026-10-20 10:10:00.000", 93), diskEv("2026-10-20 10:15:00.000", 95)}
	for _, ev := range buf {
		if !isCandidate(rs, ev) {
			t.Fatalf("событие %v должно быть кандидатом (selection, reset или close_on)", ev.Value)
		}
	}
	e.cycle(context.Background(), rs, buf)
	if inc := lastIncident(t, f); inc.Status != incidents.StatusNew || inc.EventCount != 3 {
		t.Fatalf("инцидент должен остаться открытым: %+v", inc)
	}
	if e.m.incidentsClosed.Load() != 0 {
		t.Fatal("старый замер 80 % не должен закрывать инцидент")
	}
	// Восстановление позже последнего нарушения — закрытие.
	buf = append(buf, diskEv("2026-10-20 10:20:00.000", 84))
	e.cycle(context.Background(), rs, buf)
	if inc := lastIncident(t, f); inc.Status != incidents.StatusClosed || e.m.incidentsClosed.Load() != 1 {
		t.Fatalf("восстановление должно закрыть инцидент: %+v closed=%d", inc, e.m.incidentsClosed.Load())
	}
}

// Движок без модуля Wazuh стартует без WAZUH_*: исполнитель отбрасывается,
// заглушка пароля не проверяется; с модулем — проверка как раньше.
func TestConfigureWazuh(t *testing.T) {
	acfg, _ := analyst.LoadConfig("")
	acfg.Respond.WazuhAR = &respond.WazuhAR{APIURL: "https://m:55000", Password: "change-me", Agents: "001"}
	if msg := configureWazuh(&acfg, "0", "https://m:55000", "change-me"); msg != "" || acfg.Respond.WazuhAR != nil {
		t.Fatalf("модуль выключен: msg=%q wazuh=%+v", msg, acfg.Respond.WazuhAR)
	}
	acfg.Respond.WazuhAR = nil
	if msg := configureWazuh(&acfg, "", "", ""); msg != "" {
		t.Fatalf("без переменных вообще: %q", msg)
	}
	r := respond.New(acfg.Respond)
	for _, m := range r.ConfigErrors() {
		if strings.Contains(m, "wazuh") {
			t.Fatalf("без модуля не должно быть замечаний про Wazuh: %v", r.ConfigErrors())
		}
	}
	acfg.Respond.WazuhAR = &respond.WazuhAR{APIURL: "https://m:55000", Password: "change-me", Agents: "001"}
	if msg := configureWazuh(&acfg, "1", "https://m:55000", "change-me"); msg == "" || acfg.Respond.WazuhAR == nil {
		t.Fatal("модуль включён, пароль-заглушка — отказ, исполнитель сохранён")
	}
	acfg.Respond.WazuhAR.Password = "real"
	if msg := configureWazuh(&acfg, "1", "https://m:55000", "real"); msg != "" {
		t.Fatalf("модуль включён, пароль настоящий: %q", msg)
	}
}
