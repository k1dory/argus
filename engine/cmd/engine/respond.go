package main

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
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

// reservePrefix — начало записи-резерва в response_log (запись вперёд перед
// блоком адреса склеенного инцидента); reserveRetry — пауза перед новой
// попыткой, если резерв не записался.
const (
	reservePrefix = "резерв:"
	reserveRetry  = 30 * time.Second
)

// respEntry — решение и его время.
func (e *engine) respEntry(id string) (string, time.Time) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	v := e.respState[id]
	return v.state, v.at
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
			delete(e.respCapIP, k)
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

// capReserveIP — место в потолке склеенного инцидента под адрес ip. Место
// принадлежит адресу: повтор того же адреса (после сбоя исполнителей, после
// рестарта) занимает его же место, а не новое. fresh — место занято сейчас
// (его можно вернуть capReleaseIP), ok=false — за окно уже limit адресов.
func (e *engine) capReserveIP(id, ip string, now time.Time, window time.Duration, limit int) (ok, fresh bool) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	owners := e.respCapIP[id]
	for a, at := range owners {
		if now.Sub(at) >= window {
			delete(owners, a)
		}
	}
	kept := e.respCap[id][:0]
	for _, t := range e.respCap[id] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	e.respCap[id] = kept
	if _, held := owners[ip]; held {
		return true, false
	}
	if len(kept) >= limit {
		return false, false
	}
	if owners == nil {
		owners = map[string]time.Time{}
		e.respCapIP[id] = owners
	}
	owners[ip] = now
	e.respCap[id] = append(kept, now)
	return true, true
}

// capReleaseIP — блока не было: место адреса возвращается.
func (e *engine) capReleaseIP(id, ip string) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	at, ok := e.respCapIP[id][ip]
	if !ok {
		return
	}
	delete(e.respCapIP[id], ip)
	ts := e.respCap[id]
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i].Equal(at) {
			e.respCap[id] = append(ts[:i], ts[i+1:]...)
			return
		}
	}
}

// capRestoreIP — место адреса по записи журнала (рестарт).
func (e *engine) capRestoreIP(id, ip string, at time.Time) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	if _, held := e.respCapIP[id][ip]; held {
		return
	}
	if e.respCapIP[id] == nil {
		e.respCapIP[id] = map[string]time.Time{}
	}
	e.respCapIP[id][ip] = at
	e.respCap[id] = append(e.respCap[id], at)
}

// restoreRespState — после рестарта: открытые инциденты с правилом respond
// считаются решёнными (done). Их дописывание иначе вызвало бы исполнителей
// заново: список активных блокировок в памяти и после рестарта пуст.
//
// Склеенный по подсети решается по адресам — из response_log, независимо от
// списка участников (он лишь выборка для карточки):
//   - блок или симуляция хотя бы одним исполнителем — done и место адреса;
//   - сбой исполнителей (и уведомление о повторе) — только место: очередь повторов
//     после рестарта пуста, новая сработка адреса блокирует снова на том же месте;
//   - потолок — capped; IDS, «уже заблокирован», отказ allowlist — done;
//   - ожидание доверенных событий — без решения.
//
// Перед каждым блоком в журнале есть резерв (запись вперёд). Резерв без итога —
// итог после исполнителей не записался: адрес считается заблокированным (done,
// место занято, повтора нет), в карточке — «итог не записан, проверьте NGFW».
// Если журнал недоступен — все записанные адреса решены, потолок окна исчерпан.
func (e *engine) restoreRespState(open []incidents.Incident, now time.Time) int {
	n := 0
	var collapsed []*incidents.Incident
	for i := range open {
		if incidents.IsCollapsedKey(open[i].GroupKey) {
			collapsed = append(collapsed, &open[i])
			n++
			continue
		}
		if r := e.ruleFor(open[i].RuleID); r != nil && r.Respond != nil {
			e.setRespStatus(open[i].IncidentID, "done", now)
			n++
		}
	}
	if len(collapsed) == 0 {
		return n
	}
	e.restoreCollapsed(collapsed, now)
	return n
}

// restoredState — что значила запись response_log для решения по адресу:
// blocked (блок или симуляция), failed (сбой исполнителя или уведомление о
// повторе — место в потолке, но не решение), done/capped — решение без блока,
// "" — ожидание и служебные строки.
func restoredState(row store.ResponseRow) string {
	switch {
	case strings.HasSuffix(row.Executor, ".unblock"):
		return "blocked" // блок был и уже снят
	case row.Executor != "argus" && row.OK == 1:
		return "blocked"
	case row.Executor != "argus":
		return "failed"
	case strings.HasPrefix(row.Detail, "все исполнители отказали"):
		return "failed"
	case strings.HasPrefix(row.Detail, reservePrefix):
		return "reserved"
	case strings.HasPrefix(row.Detail, "повтор отложен"):
		return ""
	case strings.HasPrefix(row.Detail, "потолок блокировок"):
		return "capped"
	case strings.HasPrefix(row.Detail, "ожидание:"), strings.HasPrefix(row.Detail, "предупреждение:"), strings.HasPrefix(row.Detail, "адресов больше"),
		strings.HasPrefix(row.Detail, "адрес не найден"):
		return ""
	default:
		return "done" // IDS, уже заблокирован, отказ по allowlist/never_block
	}
}

// respUnit — что решается автоответом отдельно: инцидент целиком или, у
// склеенного по подсети, сработка правила по одному адресу. Решение — по счёту
// доверенных событий самой сработки, а не по событиям, которые инцидент хранит
// для карточки.
type respUnit struct {
	key                string // ключ respState
	ip                 string // адрес сработки склеенного инцидента; "" — инцидент целиком
	rule               *rules.Rule
	trusted, untrusted int
	why                []string
	targets            []string
	truncated          int
}

func (e *engine) respUnits(inc *incidents.Incident) []respUnit {
	if !incidents.IsCollapsedKey(inc.GroupKey) {
		r := e.ruleFor(inc.RuleID)
		if !respondsAt(r, inc.Level) {
			return nil
		}
		trusted, untrusted, why := e.splitTrusted(inc.Events)
		u := respUnit{key: inc.IncidentID, rule: r, trusted: len(trusted), untrusted: untrusted, why: why}
		u.targets, u.truncated = r.RespondTargets(trusted)
		return []respUnit{u}
	}
	var out []respUnit
	for _, c := range inc.Candidates {
		// Решает правило сработки: адрес, по которому была только долбёжка без
		// respond, не блокируется оттого, что соседний адрес подсети сканировал.
		// Правило могли убрать reload'ом — тогда решать нечем.
		r := e.ruleFor(c.Rule)
		if r == nil || !respondsAt(r, r.Level) {
			continue
		}
		u := respUnit{key: inc.IncidentID + "|" + c.IP, ip: c.IP, rule: r, targets: []string{c.IP}}
		origins := make([]string, 0, len(c.Origins))
		for o := range c.Origins {
			origins = append(origins, o)
		}
		sort.Strings(origins)
		for _, o := range origins {
			transport, peer, _ := strings.Cut(o, "|")
			if e.resp.TrustedEvent(transport, peer) {
				u.trusted += c.Origins[o]
				continue
			}
			u.untrusted += c.Origins[o]
			if len(u.why) < 3 {
				u.why = append(u.why, fmt.Sprintf("%d событий: transport=%q peer=%q — не file/http/tls/pull и не из trusted_sources", c.Origins[o], transport, peer))
			}
		}
		out = append(out, u)
	}
	return out
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
// и сработки тех же инцидентов — читать оригиналы параллельно нельзя.
func snapshotIncidents(incs []*incidents.Incident) []*incidents.Incident {
	out := make([]*incidents.Incident, 0, len(incs))
	for _, inc := range incs {
		cp := *inc
		cp.Events = append([]*model.Event(nil), inc.Events...)
		cp.Candidates = inc.RespondCandidates()
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
		for _, u := range e.respUnits(inc) {
			if u.ip != "" {
				rows = append(rows, e.respondCollapsed(ctx, inc, u, mode, now)...)
				continue
			}
			r := u.rule
			state := e.respStatus(u.key)
			if state == "done" {
				continue
			}
			reason := r.Title + " (" + r.ID + ")"
			if need := r.RespondMinEvents(); u.trusted < need {
				if state != "waiting" {
					e.setRespStatus(u.key, "waiting", now)
					detail := fmt.Sprintf("ожидание: доверенных событий %d из %d (respond.min_events) — блокировка после следующего доверенного события в окне", u.trusted, need)
					if u.untrusted > 0 {
						// событий хватило бы, но часть — с недоверенного транспорта: это и есть «не заблокирован по недоверию»
						e.m.untrustedSkips.Add(1)
						detail += fmt.Sprintf("; не учтено недоверенных: %d — %s", u.untrusted, strings.Join(u.why, "; "))
						slog.Warn("ips: не заблокирован — недоверенный источник", "incident", inc.IncidentID, "rule", r.ID, "trusted", u.trusted, "untrusted", u.untrusted, "why", u.why[0])
					} else if u.trusted == 0 {
						detail += "; в инциденте нет событий с транспортом (восстановлен из базы?)"
					}
					rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: u.untrusted == 0, Incident: inc.IncidentID, Detail: detail}, r.ID, reason))
				}
				continue
			}
			e.setRespStatus(u.key, "done", now)
			if u.untrusted > 0 {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
					Detail: fmt.Sprintf("предупреждение: %d недоверенных событий не учтены (адреса и порог — только по %d доверенным) — %s", u.untrusted, u.trusted, strings.Join(u.why, "; "))}, r.ID, reason))
			}
			ttl, _ := time.ParseDuration(r.Respond.TTL)
			if len(u.targets) == 0 {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
					Detail: "адрес не найден в поле " + orDefault(r.Respond.Target, "src.ip") + " — блокировать нечего"}, r.ID, reason))
				continue
			}
			if u.truncated > 0 {
				rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, Incident: inc.IncidentID,
					Detail: fmt.Sprintf("адресов больше max_targets: %d отброшено", u.truncated)}, r.ID, reason))
			}
			for _, ip := range u.targets {
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
	retried := e.resp.Retry(ctx)
	e.afterRetry(retried, now)
	for _, res := range retried {
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
