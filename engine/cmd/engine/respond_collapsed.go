package main

import (
	"context"
	"errors"
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

/* ===== автомат блокировки адреса склеенного инцидента =====
   Ключ — «incident_id|адрес». У ключа один владелец за раз (respFlight): пока по
   ключу идёт попытка, параллельный вызов (соседний цикл, повтор респондера)
   выходит, ничего не трогая. Место в потолке (respCapIP) принадлежит ключу и
   освобождается только владельцем при переходе в «блока нет».

   Состояния ключа (respState): "" — ничего; waiting — мало доверенных событий;
   reserve_failed — резерв не записан, пауза reserveRetry; failed — исполнители
   отказали, место держится, повтор — респондером (через тот же путь) или новой
   сработкой, когда очередь респондера пуста; done — блок (или симуляция, или
   «уже заблокирован», или резерв без итога после рестарта); capped — потолок;
   refused — allowlist/never_block; ids — режим IDS.

   Каждая попытка, включая повтор респондера, идёт одним путём:
   место → INSERT резерва → исполнитель → итог (INSERT в конце цикла). Без
   записанного резерва исполнитель не вызывается. Таблица переходов — в описании
   PR #49 и в README «Склейка сканов по подсети». */

var errFlightBusy = errors.New("по адресу уже идёт попытка")

// beginFlight — стать владельцем ключа; false — попытка уже идёт.
func (e *engine) beginFlight(key string) bool {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	if e.respFlight[key] {
		return false
	}
	e.respFlight[key] = true
	return true
}

func (e *engine) endFlight(key string) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	delete(e.respFlight, key)
}

// writeReserve — запись-резерв перед вызовом исполнителей (запись вперёд).
func (e *engine) writeReserve(ctx context.Context, mode, incident, ip, ruleID, reason string, now time.Time) error {
	row := respRow(model.FormatTS(now)[:19], mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: ip, Incident: incident,
		Detail: reservePrefix + " блок адреса перед вызовом исполнителей"}, ruleID, reason)
	return e.ch.InsertResponses(ctx, []store.ResponseRow{row})
}

// respondCollapsed — одна сработка правила по адресу склеенного инцидента.
// Возвращает строки итога для response_log.
func (e *engine) respondCollapsed(ctx context.Context, inc *incidents.Incident, u respUnit, mode string, now time.Time) (rows []store.ResponseRow) {
	r := u.rule
	ts := model.FormatTS(now)[:19]
	reason := r.Title + " (" + r.ID + ")"
	if !e.beginFlight(u.key) {
		return nil // владелец — другой вызов; он и решит
	}
	defer e.endFlight(u.key)
	state, at := e.respEntry(u.key)
	switch {
	case state == "done" || state == "capped" || state == "refused" || state == "ids":
		return nil
	case state == "reserve_failed" && now.Sub(at) < reserveRetry:
		return nil
	case state == "failed" && e.resp.PendingIP(u.ip):
		return nil // повторит респондер — через beforeRetry, тем же путём
	}
	if need := r.RespondMinEvents(); u.trusted < need {
		if state != "waiting" {
			e.setRespStatus(u.key, "waiting", now)
			detail := fmt.Sprintf("ожидание: доверенных событий %d из %d (respond.min_events) — блокировка после следующего доверенного события в окне", u.trusted, need)
			if u.untrusted > 0 {
				e.m.untrustedSkips.Add(1)
				detail += fmt.Sprintf("; не учтено недоверенных: %d — %s", u.untrusted, strings.Join(u.why, "; "))
				slog.Warn("ips: не заблокирован — недоверенный источник", "incident", inc.IncidentID, "rule", r.ID, "trusted", u.trusted, "untrusted", u.untrusted, "why", u.why[0])
			}
			rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: u.untrusted == 0, IP: u.ip, Incident: inc.IncidentID, Detail: detail}, r.ID, reason))
		}
		return rows
	}
	if mode == respond.ModeIDS {
		e.setRespStatus(u.key, "ids", now)
		return append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: u.ip, Incident: inc.IncidentID, Detail: "режим IDS: автоответ выключен"}, r.ID, reason))
	}
	limit, window := r.IncidentCap()
	ok, fresh := e.capReserveIP(inc.IncidentID, u.ip, now, window, limit)
	if !ok {
		e.setRespStatus(u.key, "capped", now)
		slog.Warn("ips: потолок блокировок склеенного инцидента", "incident", inc.IncidentID, "rule", r.ID, "ip", u.ip, "limit", limit)
		return append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: u.ip, Incident: inc.IncidentID,
			Detail: fmt.Sprintf("потолок блокировок инцидента: %d новых адресов за %s (collapse.block_cap) — адрес не заблокирован, решение за аналитиком", limit, window)}, r.ID, reason))
	}
	// «Блока нет» освобождает место, только если его заняла эта попытка: место,
	// унаследованное от прошлой (сбой исполнителей), остаётся за ключом.
	release := func() {
		if fresh {
			e.capReleaseIP(inc.IncidentID, u.ip)
		}
	}
	if mode == respond.ModeIPS {
		if err := e.writeReserve(ctx, mode, inc.IncidentID, u.ip, r.ID, reason, now); err != nil {
			release()
			e.setRespStatus(u.key, "reserve_failed", now)
			slog.Warn("ips: резерв в response_log не записан — адрес не блокируется до следующей попытки", "incident", inc.IncidentID, "ip", u.ip, "err", err)
			return rows
		}
	}
	if u.untrusted > 0 {
		rows = append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: u.ip, Incident: inc.IncidentID,
			Detail: fmt.Sprintf("предупреждение: %d недоверенных событий не учтены (адреса и порог — только по %d доверенным) — %s", u.untrusted, u.trusted, strings.Join(u.why, "; "))}, r.ID, reason))
	}
	ttl, _ := time.ParseDuration(r.Respond.TTL)
	results, applied, err := e.resp.Auto(ctx, u.ip, inc.IncidentID, reason, ttl)
	switch {
	case err != nil:
		// отказ по allowlist/never_block — решение движка, места не занимает
		release()
		e.setRespStatus(u.key, "refused", now)
		return append(rows, respRow(ts, mode, "argus-engine", respond.Result{Executor: "argus", OK: true, IP: u.ip, Incident: inc.IncidentID, Detail: err.Error()}, r.ID, reason))
	case respond.Noop(results):
		release() // уже заблокирован другим инцидентом или оператором
		e.setRespStatus(u.key, "done", now)
		slog.Info("ips: уже заблокирован", "ip", u.ip, "incident", inc.IncidentID, "rule", r.ID, "detail", results[0].Detail)
	case applied:
		e.setRespStatus(u.key, "done", now)
		e.m.autoBlocks.Add(1)
		slog.Warn("ips: заблокирован", "ip", u.ip, "incident", inc.IncidentID, "rule", r.ID)
	case mode == respond.ModeSimulate:
		e.setRespStatus(u.key, "done", now)
		e.m.simulatedBlocks.Add(1)
	default:
		// исполнители отказали: место держится, повторит респондер тем же путём
		e.setRespStatus(u.key, "failed", now)
		e.m.blockFailures.Add(1)
		slog.Error("ips: блокировка не выполнена", "ip", u.ip, "incident", inc.IncidentID, "rule", r.ID)
	}
	for _, res := range results {
		rows = append(rows, respRow(ts, mode, "argus-engine", res, r.ID, reason))
	}
	return rows
}

// beforeRetry — хук респондера перед повтором из очереди. Для адреса склеенного
// инцидента повтор идёт тем же путём, что первая попытка: владелец ключа и
// запись-резерв. Без резерва исполнитель не вызывается. Ключ остаётся занятым до
// разбора результатов повтора (afterRetry).
func (e *engine) beforeRetry(ctx context.Context, ip, incident string) error {
	key := incident + "|" + ip
	e.respMu.Lock()
	_, tracked := e.respState[key]
	e.respMu.Unlock()
	if !tracked {
		return nil // не склеенный инцидент — как раньше
	}
	if !e.beginFlight(key) {
		return errFlightBusy
	}
	if err := e.writeReserve(ctx, respond.ModeIPS, incident, ip, "", "повтор автоблокировки", time.Now()); err != nil {
		e.endFlight(key)
		return fmt.Errorf("резерв не записан: %w", err)
	}
	e.respMu.Lock()
	e.respRetrying[key] = true
	e.respMu.Unlock()
	return nil
}

// afterRetry — итоги повторов респондера: состояние ключей, которые вёл
// beforeRetry, и освобождение владения.
func (e *engine) afterRetry(results []respond.Result, now time.Time) {
	e.respMu.Lock()
	keys := e.respRetrying
	e.respRetrying = map[string]bool{}
	e.respMu.Unlock()
	if len(keys) == 0 {
		return
	}
	outcome := map[string]string{}
	for _, res := range results {
		key := res.Incident + "|" + res.IP
		if !keys[key] {
			continue
		}
		switch {
		case res.Executor != "argus" && res.OK:
			outcome[key] = "done"
		case outcome[key] == "" && res.Noop:
			outcome[key] = "done"
		case outcome[key] == "":
			outcome[key] = "failed"
		}
	}
	for key := range keys {
		if st := outcome[key]; st != "" {
			e.setRespStatus(key, st, now)
		}
		e.endFlight(key)
	}
}

// restoreCollapsed — решения по адресам склеенных инцидентов из журнала. Состояние
// ключа определяет только ПОСЛЕДНЯЯ запись (по ts; при равном ts итог главнее
// резерва, среди итогов блок главнее сбоя) — история прежних отказов не
// учитывается. Место ключа — по времени последнего резерва (или итога, если
// резерва нет), так что продлённое место не подменяется давно истёкшим.
func (e *engine) restoreCollapsed(collapsed []*incidents.Incident, now time.Time) {
	ids := make([]string, len(collapsed))
	for i, inc := range collapsed {
		ids[i] = inc.IncidentID
	}
	rows, err := e.ch.ResponsesFor(context.Background(), ids, now.Add(-respStateTTL))
	if err != nil {
		slog.Warn("ips: решения склеенных инцидентов не восстановлены — адреса считаются решёнными, потолок исчерпанным", "err", err)
		for _, inc := range collapsed {
			for _, ip := range inc.MemberIPs() {
				e.setRespStatus(inc.IncidentID+"|"+ip, "done", now)
			}
			limit, _ := e.collapseCap(inc)
			e.respMu.Lock()
			e.respCap[inc.IncidentID] = slices.Repeat([]time.Time{now}, limit)
			e.respMu.Unlock()
		}
		return
	}
	type last struct {
		at        time.Time
		states    []string // категории записей с ts == at
		reserveAt time.Time
		slotAt    time.Time
	}
	byKey := map[string]*last{}
	var order []string
	for _, row := range rows {
		key := row.IncidentID + "|" + row.IP
		at, perr := time.ParseInLocation("2006-01-02 15:04:05", row.TS, time.UTC)
		if perr != nil {
			at = now
		}
		l := byKey[key]
		if l == nil {
			l = &last{}
			byKey[key] = l
			order = append(order, key)
		}
		st := restoredState(row)
		if st == "reserved" && at.After(l.reserveAt) {
			l.reserveAt = at
		}
		if (st == "blocked" || st == "failed" || st == "reserved") && at.After(l.slotAt) {
			l.slotAt = at
		}
		switch {
		case at.After(l.at):
			l.at, l.states = at, []string{st}
		case at.Equal(l.at):
			l.states = append(l.states, st)
		}
	}
	doubtful := 0
	for _, key := range order {
		l := byKey[key]
		id, ip, _ := strings.Cut(key, "|")
		final := lastState(l.states)
		slot := l.reserveAt
		if slot.IsZero() {
			slot = l.slotAt
		}
		switch final {
		case "reserved":
			// Резерв без итога: исполнитель мог заблокировать, итог не записался.
			e.setRespStatus(key, "done", now)
			e.capRestoreIP(id, ip, slot)
			doubtful++
		case "blocked":
			e.setRespStatus(key, "done", now)
			e.capRestoreIP(id, ip, slot)
		case "failed":
			// очередь повторов после рестарта пуста: новая сработка блокирует снова
			// на том же месте
			e.setRespStatus(key, "failed", now)
			e.capRestoreIP(id, ip, slot)
		case "":
		default:
			e.setRespStatus(key, final, now)
		}
	}
	if doubtful > 0 {
		slog.Warn("ips: резерв блока без итога в response_log — адрес считается заблокированным, место занято; проверьте NGFW", "addresses", doubtful)
	}
}

// lastState — состояние по записям последней секунды: итог главнее резерва,
// блок главнее сбоя, сбой главнее решений без блока.
func lastState(states []string) string {
	for _, want := range []string{"blocked", "failed", "capped", "refused", "done", "ids"} {
		if slices.Contains(states, want) {
			return want
		}
	}
	if slices.Contains(states, "reserved") {
		return "reserved"
	}
	return ""
}

// collapseGroupOf — группа из ключа «collapse:группа:подсеть» (в группе двоеточий
// нет, в подсети IPv6 — есть).
func collapseGroupOf(inc *incidents.Incident) string {
	group, _, _ := strings.Cut(strings.TrimPrefix(inc.GroupKey, "collapse:"), ":")
	return group
}

// collapseCap — потолок блоков склеенного инцидента: по его правилу, а если его
// убрали — по любому правилу той же группы склейки (потолок в группе один), иначе
// по умолчанию.
func (e *engine) collapseCap(inc *incidents.Incident) (int, time.Duration) {
	if r := e.ruleFor(inc.RuleID); r != nil && r.Collapsed() {
		return r.IncidentCap()
	}
	group := collapseGroupOf(inc)
	for _, r := range e.current() {
		if r.Collapsed() && r.CollapseGroup() == group {
			return r.IncidentCap()
		}
	}
	return rules.DefaultIncidentCap, rules.DefaultIncidentCapWindow
}
