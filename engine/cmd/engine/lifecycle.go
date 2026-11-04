package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

/* ===== жизненный цикл движка =====
   Цикл OOM на argus1 (02.11–04.11, 1147 kill по лимиту cgroup) почти двое суток
   был виден только в журнале Docker. Движок сам пишет в argus.events
   engine.started при старте и engine.stopped при штатной остановке (SIGTERM).
   Если при старте последнее такое событие узла — started, прошлый процесс до
   штатной остановки не дошёл: движок пишет engine.restarted с причиной (oom —
   если cgroup насчитала oom_kill, иначе unclean). Цикл ловит правило
   rules/ops/engine-restart-loop.yml за минуты. */

// lifecycleEvent — событие жизненного цикла движка (attrs.transport internal:
// пишет сам движок, снаружи это поле перезаписывает приём).
func lifecycleEvent(now time.Time, node, action, outcome string, attrs map[string]string) *model.Event {
	a := map[string]string{"transport": "internal"}
	for k, v := range attrs {
		a[k] = v
	}
	return &model.Event{
		TS: model.FormatTS(now), Source: systemSource, SourceClass: "telemetry", Vendor: "ARGUS", Product: "engine",
		Action: action, Outcome: outcome, ActorName: "argus-engine", ActorKind: "system", Node: node, Attrs: a,
	}
}

// cgroupOOMKills — счётчик oom_kill cgroup v2 контейнера (memory.events); -1 —
// не прочитан. Docker пересоздаёт cgroup при перезапуске не везде, поэтому это
// подсказка, а не доказательство.
func cgroupOOMKills(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] == "oom_kill" {
			if n, err := strconv.Atoi(f[1]); err == nil {
				return n
			}
		}
	}
	return -1
}

const cgroupMemoryEvents = "/sys/fs/cgroup/memory.events"

// restartReason — oom, только если oom_kill вырос с прошлого старта: счётчик
// накопительный, и старый OOM живой cgroup не причина нынешнего обрыва. Счётчик
// меньше прежнего — cgroup пересоздана, тогда oom — по любому ненулевому. Без
// прежнего снимка — по ненулевому.
func restartReason(prev string, cur int) string {
	if cur <= 0 {
		return "unclean"
	}
	if p, err := strconv.Atoi(prev); err == nil && cur == p {
		return "unclean"
	}
	return "oom"
}

// announceStart — engine.restarted (если прошлый запуск оборвался) и engine.started.
// Сбой хранилища не останавливает старт: событие — наблюдаемость, не условие работы.
func (e *engine) announceStart(ctx context.Context, now time.Time) {
	node := e.ch.Host()
	var events []*model.Event
	last, err := e.ch.LastEngineLifecycleRow(ctx, node)
	if err != nil {
		slog.Warn("жизненный цикл: прошлый запуск не прочитан", "err", err)
	}
	oom := cgroupOOMKills(e.cgroupEvents)
	var startAttrs map[string]string
	if oom >= 0 {
		// снимок счётчика: следующий старт считает причину по приросту
		startAttrs = map[string]string{"oom_kill": strconv.Itoa(oom)}
	}
	if last.Action == "engine.started" {
		reason := restartReason(last.OOMKill, oom)
		attrs := map[string]string{"reason": reason, "previous_start": last.At}
		if oom >= 0 {
			attrs["oom_kill"] = strconv.Itoa(oom)
		}
		e.m.uncleanRestarts.Add(1)
		slog.Error("прошлый запуск движка оборвался без штатной остановки", "reason", reason, "previous_start", last.At, "oom_kill", oom, "oom_kill_at_start", last.OOMKill)
		events = append(events, lifecycleEvent(now, node, "engine.restarted", "failure", attrs))
	}
	events = append(events, lifecycleEvent(now, node, "engine.started", "success", startAttrs))
	if err := e.ch.InsertEvents(ctx, events); err != nil {
		slog.Warn("жизненный цикл: события старта не записаны", "err", err)
	}
}

// announceStop — engine.stopped при штатной остановке: ctx уже отменён, запись — с
// собственным коротким таймаутом.
func (e *engine) announceStop(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.ch.InsertEvents(ctx, []*model.Event{lifecycleEvent(now, e.ch.Host(), "engine.stopped", "success", nil)}); err != nil {
		slog.Warn("жизненный цикл: engine.stopped не записан — следующий старт посчитает остановку оборванной", "err", err)
	}
}
