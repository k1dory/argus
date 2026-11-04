package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/devitex-soft/argus/engine/internal/rules"
)

// node — узел событий движка: хост ClickHouse, как у diskEvent (без хранилища — argus-engine).
func (e *engine) node() string {
	if e.ch == nil {
		return "argus-engine"
	}
	return e.ch.Host()
}

/* ===== отказ правил: видимая сигнализация =====
   Отвергнутое правило (неизвестное поле детекта, повтор id, ошибка разбора) не
   работает: на старте его просто нет, при перечитывании действует прежняя версия.
   Это тихое выключение детекта, поэтому движок пишет в argus.events событие
   rulesRejectedEvent (system.go): source argus.system / action rules.rejected,
   object — файл правила, attrs.rule_id, attrs.reason — код причины без содержимого
   правила, attrs.transport: internal (снаружи это поле перезаписывает коллектор,
   подделать событие через ingest нельзя); когда файл снова загрузился —
   rules.recovered. Инцидент заводит обычное правило rules/ops/rules-rejected.yml;
   метрика — argus_engine_rules_rejected. */

// noteRejected — rules.rejected на каждый отвергнутый файл. rules.recovered —
// noteRecovered, по открытым инцидентам.
func (e *engine) noteRejected(rejected []rules.RuleError, _ []*rules.Rule, now time.Time) {
	if e.rulesBad == nil {
		e.rulesBad = map[string]bool{}
	}
	bad := map[string]bool{}
	for _, re := range rejected {
		bad[re.File] = true
		e.rulesPending = append(e.rulesPending, rulesRejectedEvent(now, e.node(), re.File, re.ID, re.Reason))
	}
	e.rulesBad = bad
	if n := len(e.rulesPending); n > 1000 {
		e.rulesPending = e.rulesPending[n-1000:]
	}
}

// noteRecovered — rules.recovered по каждому файлу, по которому открыт инцидент
// правила отказа (selection action: rules.rejected) и который сейчас загружен: не по
// памяти о прошлых отказах, а по открытым инцидентам реестра — переживает рестарт и
// временное исчезновение файла. Вызывающий держит reloadMu.
func (e *engine) noteRecovered(now time.Time) {
	e.sysMu.Lock()
	reg := e.reg
	e.sysMu.Unlock()
	if reg == nil {
		return
	}
	loaded := map[string]string{}
	var watch []string
	for _, r := range e.current() {
		loaded[r.File] = r.ID
		if a, _ := r.Detection.Selection["action"].(string); a == "rules.rejected" {
			watch = append(watch, r.ID)
		}
	}
	for _, ruleID := range watch {
		for _, file := range reg.OpenGroupKeys(ruleID) {
			if id, ok := loaded[file]; ok && !e.rulesBad[file] {
				ev := rulesRejectedEvent(now, e.node(), file, id, "")
				ev.Action, ev.Outcome = "rules.recovered", "success"
				e.rulesPending = append(e.rulesPending, ev)
			}
		}
	}
}

// flushRulesEvents — записать накопленные события отказа правил; сбой — повтор позже.
func (e *engine) flushRulesEvents(ctx context.Context) {
	e.reloadMu.Lock()
	pending := e.rulesPending
	e.rulesPending = nil
	e.reloadMu.Unlock()
	if len(pending) == 0 || e.ch == nil {
		return
	}
	if err := e.ch.InsertEvents(ctx, pending); err != nil {
		slog.Warn("rules events insert", "err", err)
		e.reloadMu.Lock()
		e.rulesPending = append(pending, e.rulesPending...)
		e.reloadMu.Unlock()
	}
}
