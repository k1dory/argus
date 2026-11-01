package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

/* ===== автоответ (IPS/IDS) =====
   Правило с блоком respond при создании инцидента отдаёт адреса на блокировку.
   Что с ними делать, решает режим движка (respond.mode, переопределяется
   из консоли через console_settings.respond_mode): ids — ничего, simulate —
   только журнал, ips — блокировка на TTL. Всё пишется в response_log.

   Два предохранителя перед исполнителями, и они работают вместе:
   - доверие к источнику: событие считается основанием для блокировки, только
     если пришло по транспорту, где адрес отправителя нельзя подделать
     (attrs.transport ∈ file/http/tls/pull), либо от пира из
     respond.trusted_sources. Недоверенные события цепочки не накладывают вето
     на инцидент — они просто не учитываются: ни в счёте min_events, ни как
     источник адресов. Иначе один спуфленный UDP-syslog «гасил» бы блокировку
     по настоящим событиям;
   - respond.min_events: блокировать, когда доверенных событий накопилось не
     меньше порога (инцидент дописывается в окне dedupe). Пока их меньше —
     состояние waiting, а не done: следующие доверенные события дотянут до
     порога; недоверенные попадают в журнал предупреждением.

   Решение по инциденту (respState) живёт в памяти: после рестарта открытые
   инциденты с правилом respond считаются решёнными, чтобы их дописывание не
   вызывало исполнителей повторно (список активных блокировок тоже в памяти). */

func respRow(ts, mode, actor string, res respond.Result, ruleID, reason string) store.ResponseRow {
	return store.ResponseRow{TS: ts, IncidentID: res.Incident, RuleID: ruleID, IP: res.IP, Mode: mode, Executor: res.Executor,
		DryRun: b2u(res.DryRun || mode == respond.ModeSimulate), OK: b2u(res.OK), Detail: res.Detail, Reason: reason, Actor: actor}
}

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// respStatus — что автоответ уже решил по инциденту ("" — ещё ничего).
func (e *engine) respStatus(id string) string {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	return e.respState[id].state
}

func (e *engine) setRespStatus(id, state string, now time.Time) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	if len(e.respState) > 10000 {
		e.pruneRespStateLocked(now, respStateTTL)
	}
	e.respState[id] = respEntry{state: state, at: now}
}

const (
	respStateTTL    = 48 * time.Hour // решение старше — инцидент давно закрыт или пересоздан
	respPruneCycles = 100            // чистка respState по возрасту раз в столько циклов
)

// pruneRespState — чистка решений по возрасту (раз в respPruneCycles циклов
// из cycle, а не только при переполнении: иначе память росла бы до 10000
// записей и держалась там). Возвращает число удалённых.
func (e *engine) pruneRespState(now time.Time, ttl time.Duration) int {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	return e.pruneRespStateLocked(now, ttl)
}

func (e *engine) pruneRespStateLocked(now time.Time, ttl time.Duration) int {
	e.pruneKeysLocked(now, ttl)
	n := 0
	for k, v := range e.respState {
		if now.Sub(v.at) > ttl {
			delete(e.respState, k)
			n++
		}
	}
	return n
}

// restoreRespState — после рестарта: открытые инциденты с правилом respond
// считаются решёнными (done). Их дописывание иначе вызвало бы исполнителей
// заново: список активных блокировок в памяти и после рестарта пуст.
func (e *engine) restoreRespState(open []incidents.Incident, now time.Time) int {
	n := 0
	for i := range open {
		if r := e.ruleFor(open[i].RuleID); r != nil && r.Respond != nil {
			e.setRespStatus(open[i].IncidentID, "done", now)
			n++
		}
	}
	return n
}

// splitTrusted — доверенное подмножество событий цепочки и причины, по
// которым остальные не учитываются (не больше трёх, чтобы не раздувать журнал).
func (e *engine) splitTrusted(inc *incidents.Incident) (trusted []*model.Event, untrusted int, why []string) {
	for _, ev := range inc.Events {
		transport, peer := ev.Attrs["transport"], ev.Attrs["peer"]
		if e.resp.TrustedEvent(transport, peer) {
			trusted = append(trusted, ev)
			continue
		}
		untrusted++
		if len(why) < 3 {
			why = append(why, fmt.Sprintf("событие %s от %s: transport=%q peer=%q — не file/http/tls/pull и не из trusted_sources",
				ev.TS, orDefault(ev.Source, "?"), transport, peer))
		}
	}
	return trusted, untrusted, why
}

// snapshotIncidents — копии инцидентов для autoRespond: реагирование идёт в
// своей горутине, а Apply следующего цикла перезаписывает Events/EventCount
// тех же инцидентов — читать оригиналы параллельно нельзя.
func snapshotIncidents(incs []*incidents.Incident) []*incidents.Incident {
	out := make([]*incidents.Incident, 0, len(incs))
	for _, inc := range incs {
		cp := *inc
		cp.Events = append([]*model.Event(nil), inc.Events...)
		out = append(out, &cp)
	}
	return out
}

// autoRespond — реакция на новые и дописанные инциденты (см. шапку файла).
func (e *engine) autoRespond(ctx context.Context, incs []*incidents.Incident, now time.Time) {
	var rows []store.ResponseRow
	ts := model.FormatTS(now)[:19]
	mode, _ := e.resp.Mode()
	ready := false
	for _, inc := range incs {
		r := e.ruleFor(inc.RuleID)
		if r == nil || r.Respond == nil {
			continue
		}
		// Без прочитанного журнала решения по адресам неизвестны: новых блоков нет,
		// инцидент не помечается — решит следующий цикл, когда журнал прочитается.
		if !ready {
			if ready = e.respReady(ctx, now); !ready {
				break
			}
		}
		minLevel := r.Respond.MinLevel
		if minLevel == "" {
			minLevel = "high"
		}
		if rules.LevelRank(inc.Level) < rules.LevelRank(minLevel) {
			continue
		}
		state := e.respStatus(inc.IncidentID)
		if state == "done" {
			continue
		}
		reason := inc.RuleTitle + " (" + inc.RuleID + ")"
		trusted, untrusted, why := e.splitTrusted(inc)
		if need := r.RespondMinEvents(); len(trusted) < need {
			if state != "waiting" {
				e.setRespStatus(inc.IncidentID, "waiting", now)
				detail := fmt.Sprintf("ожидание: доверенных событий %d из %d (respond.min_events) — блокировка после следующего доверенного события в окне", len(trusted), need)
				if untrusted > 0 {
					// событий хватило бы, но часть — с недоверенного транспорта: это и есть «не заблокирован по недоверию»
					e.m.untrustedSkips.Add(1)
					detail += fmt.Sprintf("; не учтено недоверенных: %d — %s", untrusted, strings.Join(why, "; "))
					slog.Warn("ips: не заблокирован — недоверенный источник", "incident", inc.IncidentID, "rule", inc.RuleID, "trusted", len(trusted), "untrusted", untrusted, "why", why[0])
				} else if len(inc.Events) == 0 {
					detail += "; в инциденте нет событий с транспортом (восстановлен из базы?)"
				}
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: untrusted == 0, Incident: inc.IncidentID, Detail: detail}, inc.RuleID, reason))
			}
			continue
		}
		e.setRespStatus(inc.IncidentID, "done", now)
		if untrusted > 0 {
			rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
				Detail: fmt.Sprintf("предупреждение: %d недоверенных событий не учтены (адреса и порог — только по %d доверенным) — %s", untrusted, len(trusted), strings.Join(why, "; "))}, inc.RuleID, reason))
		}
		ttl, _ := time.ParseDuration(r.Respond.TTL)
		targets, truncated := r.RespondTargets(trusted)
		if len(targets) == 0 {
			rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
				Detail: "адрес не найден в поле " + orDefault(r.Respond.Target, "src.ip") + " — блокировать нечего"}, inc.RuleID, reason))
			continue
		}
		if truncated > 0 {
			rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
				Detail: fmt.Sprintf("адресов больше max_targets: %d отброшено", truncated)}, inc.RuleID, reason))
		}
		for _, target := range targets {
			ip, ok := respond.CanonicalIP(target)
			if !ok {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: target, Incident: inc.IncidentID,
					Detail: fmt.Sprintf("адрес %q не разбирается — не блокируется", target)}, inc.RuleID, reason))
				continue
			}
			rows = append(rows, e.attemptKey(ctx, respKey{incident: inc.IncidentID, ip: ip, ruleID: inc.RuleID, reason: reason, ttl: ttl}, now)...)
		}
	}
	if len(rows) > 0 {
		if err := e.ch.InsertResponses(ctx, rows); err != nil {
			slog.Warn("response_log insert", "err", err)
		}
	}
}

// expireBlocks — снятие по TTL и повторы неудачных автоблокировок. Повторы —
// автоматом ключей (retryKeys), тем же путём с резервом, что и первая попытка.
func (e *engine) expireBlocks(ctx context.Context, now time.Time) {
	ts := model.FormatTS(now)[:19]
	var rows []store.ResponseRow
	for _, res := range e.resp.Expire(ctx) {
		rows = append(rows, respRow(ts, "ips", "argus-engine", res, "", "TTL истёк"))
	}
	if e.respReady(ctx, now) {
		rows = append(rows, e.retryKeys(ctx, now)...)
	}
	if len(rows) == 0 {
		return
	}
	if err := e.ch.InsertResponses(ctx, rows); err != nil {
		slog.Warn("response_log insert", "err", err)
	}
}
