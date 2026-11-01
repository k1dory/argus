package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
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
   вызывало исполнителей повторно (список активных блокировок тоже в памяти).

   Склеенный по подсети инцидент (rules.Collapse) решается по каждому адресу
   отдельно: ключ «incident_id|адрес», события и min_events — этого адреса.
   Новый адрес подсети блокируется, даже когда первый уже done. Общий потолок —
   collapse.block_cap новых блокировок на инцидент за окно: сверх него адрес
   не блокируется (capped), в журнал — «потолок блокировок, решение за аналитиком». */

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
	n := 0
	for k, v := range e.respState {
		if now.Sub(v.at) > ttl {
			delete(e.respState, k)
			n++
		}
	}
	for k, ts := range e.respCap {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) > ttl {
			delete(e.respCap, k)
		}
	}
	return n
}

// capReserve — занять место под блокировку нового адреса склеенного
// инцидента: false — за окно уже limit блокировок. Проверка и запись под
// одной блокировкой: автоответы соседних циклов идут параллельно.
func (e *engine) capReserve(id string, now time.Time, window time.Duration, limit int) bool {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	kept := e.respCap[id][:0]
	for _, t := range e.respCap[id] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		e.respCap[id] = kept
		return false
	}
	e.respCap[id] = append(kept, now)
	return true
}

// capRelease — блокировки не было (отказ по allowlist, IDS, адрес уже
// заблокирован, сбой исполнителя): место возвращается.
func (e *engine) capRelease(id string, at time.Time) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	ts := e.respCap[id]
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(at) {
			e.respCap[id] = append(ts[:i], ts[i+1:]...)
			return
		}
	}
}

// restoreRespState — после рестарта: открытые инциденты с правилом respond
// считаются решёнными (done). Их дописывание иначе вызвало бы исполнителей
// заново: список активных блокировок в памяти и после рестарта пуст.
// Склеенный по подсети решается по адресам: решения и потраченный потолок
// восстанавливаются из response_log (членство в инциденте само по себе не
// значит, что адрес блокировали). Если журнал недоступен — осторожно: все
// записанные адреса решены, потолок окна считается исчерпанным.
func (e *engine) restoreRespState(open []incidents.Incident, now time.Time) int {
	n := 0
	var collapsed []string
	byID := map[string]*incidents.Incident{}
	for i := range open {
		r := e.ruleFor(open[i].RuleID)
		if incidents.IsCollapsedKey(open[i].GroupKey) {
			collapsed = append(collapsed, open[i].IncidentID)
			byID[open[i].IncidentID] = &open[i]
			n++
			continue
		}
		if r != nil && r.Respond != nil {
			e.setRespStatus(open[i].IncidentID, "done", now)
			n++
		}
	}
	if len(collapsed) == 0 {
		return n
	}
	rows, err := e.ch.ResponsesFor(context.Background(), collapsed, now.Add(-respStateTTL))
	if err != nil {
		slog.Warn("ips: решения склеенных инцидентов не восстановлены — адреса считаются решёнными, потолок исчерпанным", "err", err)
		for _, id := range collapsed {
			inc := byID[id]
			for _, ip := range inc.MemberIPs() {
				e.setRespStatus(id+"|"+ip, "done", now)
			}
			if r := e.ruleFor(inc.RuleID); r != nil {
				limit, _ := r.IncidentCap()
				e.respMu.Lock()
				e.respCap[id] = slices.Repeat([]time.Time{now}, limit)
				e.respMu.Unlock()
			}
		}
		return n
	}
	for _, row := range rows {
		key := row.IncidentID + "|" + row.IP
		at, perr := time.ParseInLocation("2006-01-02 15:04:05", row.TS, time.UTC)
		if perr != nil {
			at = now
		}
		switch state := restoredState(row); state {
		case "blocked":
			e.setRespStatus(key, "done", now)
			e.respMu.Lock()
			e.respCap[row.IncidentID] = append(e.respCap[row.IncidentID], at)
			e.respMu.Unlock()
		case "failed":
			// Блок не вышел, повтор responder'а после рестарта потерян: адрес не решён,
			// но место в потолке он держал — держит и теперь.
			e.respMu.Lock()
			e.respCap[row.IncidentID] = append(e.respCap[row.IncidentID], at)
			e.respMu.Unlock()
		case "":
		default:
			e.setRespStatus(key, state, now)
		}
	}
	return n
}

// restoredState — что значила запись response_log для решения по адресу:
// blocked (блок или симуляция — done и место в потолке), failed (сбой
// исполнителя — только место), done/capped — решение без блока, "" — ожидание.
func restoredState(row store.ResponseRow) string {
	switch {
	case strings.HasSuffix(row.Executor, ".unblock"):
		return "done" // блок был и уже снят
	case row.Executor != "argus" && row.OK == 1:
		return "blocked"
	case row.Executor != "argus":
		return "failed"
	case strings.HasPrefix(row.Detail, "потолок блокировок"):
		return "capped"
	case strings.HasPrefix(row.Detail, "ожидание:"), strings.HasPrefix(row.Detail, "предупреждение:"), strings.HasPrefix(row.Detail, "адресов больше"):
		return ""
	default:
		return "done" // IDS, уже заблокирован, отказ по allowlist/never_block
	}
}

// respUnit — что решается автоответом отдельно: инцидент целиком или, у
// склеенного по подсети, один его адрес со своими событиями.
type respUnit struct {
	key    string // ключ respState
	ip     string // адрес участника склеенного инцидента; "" — инцидент целиком
	events []*model.Event
}

func respUnits(inc *incidents.Incident) []respUnit {
	if !incidents.IsCollapsedKey(inc.GroupKey) {
		return []respUnit{{key: inc.IncidentID, events: inc.Events}}
	}
	get := rules.Getter("src.ip")
	by := map[string][]*model.Event{}
	var order []string
	for _, ev := range inc.Events {
		ip := strings.TrimSpace(get(ev))
		if ip == "" {
			continue
		}
		if _, ok := by[ip]; !ok {
			order = append(order, ip)
		}
		by[ip] = append(by[ip], ev)
	}
	units := make([]respUnit, 0, len(order))
	for _, ip := range order {
		units = append(units, respUnit{key: inc.IncidentID + "|" + ip, ip: ip, events: by[ip]})
	}
	return units
}

// splitTrusted — доверенное подмножество событий цепочки и причины, по
// которым остальные не учитываются (не больше трёх, чтобы не раздувать журнал).
func (e *engine) splitTrusted(events []*model.Event) (trusted []*model.Event, untrusted int, why []string) {
	for _, ev := range events {
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
	for _, inc := range incs {
		collapsed := incidents.IsCollapsedKey(inc.GroupKey)
		if r := e.ruleFor(inc.RuleID); !collapsed && !respondsAt(r, inc.Level) {
			continue
		}
		for _, u := range respUnits(inc) {
			// У склеенного инцидента правило решения — сработавшее по этому адресу:
			// адрес, по которому была только долбёжка без respond, не блокируется
			// оттого, что соседний адрес подсети сканировал.
			r := e.ruleFor(inc.RuleID)
			if collapsed {
				r = nil
				for _, id := range inc.MemberRules(u.ip) {
					// Правило могли удалить reload'ом, а его id остался в истории адреса.
					if rr := e.ruleFor(id); rr != nil && respondsAt(rr, rr.Level) {
						r = rr
						break
					}
				}
				if r == nil {
					continue
				}
			}
			state := e.respStatus(u.key)
			if state == "done" || state == "capped" {
				continue
			}
			reason := r.Title + " (" + r.ID + ")"
			trusted, untrusted, why := e.splitTrusted(u.events)
			if need := r.RespondMinEvents(); len(trusted) < need {
				if state != "waiting" {
					e.setRespStatus(u.key, "waiting", now)
					detail := fmt.Sprintf("ожидание: доверенных событий %d из %d (respond.min_events) — блокировка после следующего доверенного события в окне", len(trusted), need)
					if untrusted > 0 {
						// событий хватило бы, но часть — с недоверенного транспорта: это и есть «не заблокирован по недоверию»
						e.m.untrustedSkips.Add(1)
						detail += fmt.Sprintf("; не учтено недоверенных: %d — %s", untrusted, strings.Join(why, "; "))
						slog.Warn("ips: не заблокирован — недоверенный источник", "incident", inc.IncidentID, "rule", r.ID, "trusted", len(trusted), "untrusted", untrusted, "why", why[0])
					} else if len(u.events) == 0 {
						detail += "; в инциденте нет событий с транспортом (восстановлен из базы?)"
					}
					rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: untrusted == 0, IP: u.ip, Incident: inc.IncidentID, Detail: detail}, r.ID, reason))
				}
				continue
			}
			reserved := false
			if u.ip != "" && mode != respond.ModeIDS {
				if limit, window := r.IncidentCap(); !e.capReserve(inc.IncidentID, now, window, limit) {
					e.setRespStatus(u.key, "capped", now)
					rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: u.ip, Incident: inc.IncidentID,
						Detail: fmt.Sprintf("потолок блокировок инцидента: %d новых адресов за %s (collapse.block_cap) — адрес не заблокирован, решение за аналитиком", limit, window)}, r.ID, reason))
					slog.Warn("ips: потолок блокировок склеенного инцидента", "incident", inc.IncidentID, "rule", r.ID, "ip", u.ip, "limit", limit)
					continue
				}
				reserved = true
			}
			e.setRespStatus(u.key, "done", now)
			if untrusted > 0 {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
					Detail: fmt.Sprintf("предупреждение: %d недоверенных событий не учтены (адреса и порог — только по %d доверенным) — %s", untrusted, len(trusted), strings.Join(why, "; "))}, r.ID, reason))
			}
			ttl, _ := time.ParseDuration(r.Respond.TTL)
			targets, truncated := r.RespondTargets(trusted)
			if len(targets) == 0 {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
					Detail: "адрес не найден в поле " + orDefault(r.Respond.Target, "src.ip") + " — блокировать нечего"}, r.ID, reason))
				if reserved {
					e.capRelease(inc.IncidentID, now)
				}
				continue
			}
			if truncated > 0 {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
					Detail: fmt.Sprintf("адресов больше max_targets: %d отброшено", truncated)}, r.ID, reason))
			}
			for _, ip := range targets {
				results, applied, err := e.resp.Auto(ctx, ip, inc.IncidentID, reason, ttl)
				if err != nil {
					// отказ по allowlist/адресу — не ошибка исполнителя, а решение движка
					rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: ip, Incident: inc.IncidentID, Detail: err.Error()}, r.ID, reason))
					continue
				}
				if mode == respond.ModeIDS {
					rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: ip, Incident: inc.IncidentID, Detail: "режим IDS: автоответ выключен"}, r.ID, reason))
					continue
				}
				for _, res := range results {
					rows = append(rows, respRow(ts, mode, "argus-engine", res, r.ID, reason))
				}
				// Место потрачено блоком или симуляцией. Сбой всех исполнителей тоже держит
				// место: responder повторит блок сам (Retry), и повтор должен уложиться в
				// тот же потолок. Возвращается место только без блока: отказ по
				// allowlist/never_block, IDS, адрес уже заблокирован.
				if applied || mode == respond.ModeSimulate || (!respond.Noop(results) && len(results) > 0) {
					reserved = false
				}
				switch {
				case applied:
					e.m.autoBlocks.Add(1)
					slog.Warn("ips: заблокирован", "ip", ip, "incident", inc.IncidentID, "rule", r.ID)
				case mode == respond.ModeSimulate:
					e.m.simulatedBlocks.Add(1)
				case respond.Noop(results):
					// уже заблокирован (другим инцидентом или оператором) — делать нечего, не отказ
					slog.Info("ips: уже заблокирован", "ip", ip, "incident", inc.IncidentID, "rule", r.ID, "detail", results[0].Detail)
				default:
					e.m.blockFailures.Add(1)
					slog.Error("ips: блокировка не выполнена", "ip", ip, "incident", inc.IncidentID, "rule", r.ID)
				}
			}
			if reserved {
				e.capRelease(inc.IncidentID, now)
			}
		}
	}
	if len(rows) > 0 {
		if err := e.ch.InsertResponses(ctx, rows); err != nil {
			slog.Warn("response_log insert", "err", err)
		}
	}
}

// expireBlocks — снятие по TTL и повторы неудачных автоблокировок.
func (e *engine) expireBlocks(ctx context.Context, now time.Time) {
	ts := model.FormatTS(now)[:19]
	var rows []store.ResponseRow
	for _, res := range e.resp.Expire(ctx) {
		rows = append(rows, respRow(ts, "ips", "argus-engine", res, "", "TTL истёк"))
	}
	for _, res := range e.resp.Retry(ctx) {
		rows = append(rows, respRow(ts, "ips", "argus-engine", res, "", "повтор автоблокировки"))
		if res.OK && res.Executor != "argus" {
			e.m.autoBlocks.Add(1)
		}
	}
	if len(rows) == 0 {
		return
	}
	if err := e.ch.InsertResponses(ctx, rows); err != nil {
		slog.Warn("response_log insert", "err", err)
	}
}

// respondsAt — у правила есть respond и уровень не ниже его min_level.
func respondsAt(r *rules.Rule, level string) bool {
	if r == nil || r.Respond == nil {
		return false
	}
	minLevel := r.Respond.MinLevel
	if minLevel == "" {
		minLevel = "high"
	}
	return rules.LevelRank(level) >= rules.LevelRank(minLevel)
}
