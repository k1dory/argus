package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/store"
)

/* ===== системные события и инциденты движка =====
   Сторож диска: переполненный диск ClickHouse — самый частый способ тихо
   потерять SIEM: вставки отклоняются, коллектор копит очередь, а дежурный
   узнаёт через день. Раз в цикл движок читает system.disks и пишет в
   argus.events одно событие телеметрии о самом заполненном диске (source
   argus.system, action disk.usage, value — занятость в процентах). Инцидент
   по нему заводит обычное правило rules/ops/argus-disk-low.yml: порог и
   закрытие описаны там же, где и остальные правила, а не в коде.

   Шторм: если за цикл правило дало больше ARGUS_MAX_NEW_INCIDENTS новых
   инцидентов, лишние не заводятся, а вместо них один инцидент «шторм событий
   по правилу X» с числом отброшенных; закрывается сам, когда шторм стих. */

const (
	systemSource = "argus.system"
	stormRuleID  = "argus.system.storm"
)

// checkDisks — замер самого заполненного диска ClickHouse: метрика
// argus_clickhouse_disk_free_ratio и событие телеметрии в argus.events.
func (e *engine) checkDisks(ctx context.Context, now time.Time) {
	disks, err := e.ch.Disks(ctx)
	if err != nil || len(disks) == 0 {
		return
	}
	worst := disks[0]
	ratio := 1.0
	for _, d := range disks {
		if r := float64(d.Free) / float64(d.Total); r < ratio {
			ratio, worst = r, d
		}
	}
	e.m.diskFreePermille.Store(int64(ratio * 1000))
	ev := diskEvent(now, e.ch.Host(), worst, ratio)
	if err := e.ch.InsertEvents(ctx, []*model.Event{ev}); err != nil {
		slog.Warn("disk telemetry insert", "err", err)
		return
	}
	if ev.Value >= 90 {
		slog.Warn("disk low", "node", ev.Node, "disk", worst.Name, "used_percent", ev.Value)
	}
}

// diskEvent — событие единой схемы о занятости диска: value — процент
// занятого места (одна десятая), object — путь диска, attrs — абсолютные
// числа для разбора.
func diskEvent(now time.Time, node string, d store.Disk, freeRatio float64) *model.Event {
	ev := &model.Event{
		TS: model.FormatTS(now), Source: systemSource, SourceClass: "telemetry", Vendor: "ARGUS", Product: "engine",
		Action: "disk.usage", Outcome: "unknown", ActorName: "argus-engine", ActorKind: "system",
		Object: d.Path, Node: node, Value: math.Round((1-freeRatio)*1000) / 10, Unit: "percent",
		Attrs: map[string]string{"disk": d.Name, "free_bytes": strconv.FormatUint(d.Free, 10), "total_bytes": strconv.FormatUint(d.Total, 10)},
	}
	ev.Ensure()
	return ev
}

// stormIncidents — по отброшенным сработкам: завести или дописать инцидент
// «шторм» на правило, закрыть стихшие. Возвращает инциденты к записи.
func (e *engine) stormIncidents(ctx context.Context, dropped map[string]int, now time.Time) []*incidents.Incident {
	e.sysMu.Lock()
	defer e.sysMu.Unlock()
	ts := model.FormatTS(now)[:19]
	var out []*incidents.Incident
	ruleIDs := make([]string, 0, len(dropped))
	for id := range dropped {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		n := dropped[ruleID]
		e.m.incidentsDropped.Add(int64(n))
		title := ruleID
		if r := e.ruleFor(ruleID); r != nil {
			title = r.Title
		}
		line := fmt.Sprintf("%s · за цикл отброшено %d новых инцидентов сверх предела ARGUS_MAX_NEW_INCIDENTS", ts, n)
		inc := e.storms[ruleID]
		if inc == nil {
			inc = e.reg.OpenByRuleActor(stormRuleID, ruleID)
		}
		if inc != nil && inc.Status != incidents.StatusClosed && inc.Status != incidents.StatusFalsePositive {
			inc.EventCount++
			inc.LastTS, inc.UpdatedAt = ts, ts
			if len(inc.Chain) >= 12 {
				inc.Chain = inc.Chain[1:]
			}
			inc.Chain = append(inc.Chain, line)
			e.storms[ruleID] = inc
			out = append(out, inc)
			continue
		}
		id, _ := e.reg.NextID()
		inc = &incidents.Incident{
			IncidentID: id, UpdatedAt: ts, CreatedAt: ts, RuleID: stormRuleID,
			RuleTitle: "Шторм событий по правилу «" + title + "»", Level: "high", Tags: []string{"argus.system", "ops.storm"},
			Status: incidents.StatusNew, ActorName: ruleID, Node: "argus-engine", Sources: []string{"argus.system"},
			EventCount: 1, FirstTS: ts, LastTS: ts, Chain: []string{line},
			Note: "Системный инцидент движка: правило " + ruleID + " заводит больше инцидентов за цикл, чем разрешено. Обычно это шумный источник или слишком широкое правило — проверьте selection/threshold и исключения. Лишние инциденты не заведены, события в базе сохранены.",
		}
		e.reg.AddSystem(inc)
		e.storms[ruleID] = inc
		e.m.incidentsCreated.Add(1)
		slog.Error("storm", "id", id, "rule", ruleID, "dropped", n)
		e.notifyAll(ctx, inc)
		out = append(out, inc)
	}
	// стихло: 15 минут без отброшенных — закрываем
	for ruleID, inc := range e.storms {
		if dropped[ruleID] > 0 {
			continue
		}
		last := (&model.Event{TS: inc.LastTS}).Time()
		if inc.Status == incidents.StatusClosed || inc.Status == incidents.StatusFalsePositive {
			delete(e.storms, ruleID)
			continue
		}
		if last.IsZero() || now.Sub(last) < 15*time.Minute {
			continue
		}
		inc.Status, inc.UpdatedAt = incidents.StatusClosed, ts
		inc.Note = strings.TrimSpace(inc.Note + "\n" + ts + " · закрыт автоматикой: шторм стих")
		delete(e.storms, ruleID)
		e.m.incidentsClosed.Add(1)
		out = append(out, inc)
	}
	return out
}
