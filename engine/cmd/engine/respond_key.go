package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/rules"
	"github.com/devitex-soft/argus/engine/internal/store"
)

/* ===== автомат блокировки адреса =====
   Ключ — «incident_id|адрес», адрес канонический (respond.CanonicalIP). У ключа
   один владелец за раз (respFlight): пока по ключу идёт попытка, второй вызов —
   соседний цикл или повтор — выходит, ничего не трогая.

   Любая попытка, первая или повтор, идёт одним путём (attemptKey): снимок режима
   → место в потолке → INSERT резерва → исполнитель → итог. Без записанного
   резерва исполнитель не вызывается (fail-closed). Повторы ведёт сам движок
   (retryKeys из expireBlocks), очередь Retry респондера автоблокировки не видят.

   Место в потолке (respond.block_cap на правило и подсеть /24 или /48 за окно)
   принадлежит ключу; повтор того же ключа своё место не перезанимает, пока оно в
   окне; освобождает место только владелец, при переходе в «блока нет».

   Таблица переходов — README «Автоответ: потолок и запись вперёд». */

// Состояния ключа.
const (
	keyFailed        = "failed"         // исполнители отказали; место держится, повтор по расписанию
	keyReserveFailed = "reserve_failed" // резерв не записан; места нет, повтор после паузы
	keyDone          = "done"           // блок стоит (или симуляция, или уже был, или резерв без итога)
	keyExhausted     = "exhausted"      // попытки исчерпаны; место держится, решение за аналитиком
	keyCapped        = "capped"         // потолок; решение за аналитиком
	keyRefused       = "refused"        // allowlist / never_block / служебный адрес
	keyIDS           = "ids"            // режим IDS
	keyManual        = "manual"         // оператор заблокировал или снял адрес вручную
)

// Шаги в response_log.step (миграция 0037).
const (
	stepReserve   = "reserve"
	stepBlocked   = "blocked"
	stepNoop      = "noop"
	stepSimulated = "simulated"
	stepFailed    = "failed"
	stepExhausted = "exhausted"
	stepCapped    = "capped"
	stepRefused   = "refused"
	stepIDS       = "ids"
	stepManual    = "manual"
)

// reserveRetry — пауза перед новой попыткой после незаписанного резерва.
const reserveRetry = time.Minute

// respKey — состояние ключа и всё, что нужно для повтора без инцидента.
type respKey struct {
	state     string
	at        time.Time
	incident  string
	ip        string
	ruleID    string
	reason    string
	ttl       time.Duration
	attempts  int
	next      time.Time // срок повтора (failed)
	slotSpace string    // пространство места: режим, в котором оно занято
}

func keyOf(incident, ip string) string { return incident + "|" + ip }

func terminal(state string) bool {
	switch state {
	case keyDone, keyExhausted, keyCapped, keyRefused, keyIDS, keyManual:
		return true
	}
	return false
}

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

// keySnapshot — копия состояния ключа (nil — решения нет).
func (e *engine) keySnapshot(key string) *respKey {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	if k := e.respKeys[key]; k != nil {
		cp := *k
		return &cp
	}
	return nil
}

func (e *engine) storeKey(key string, k respKey) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	if cur := e.respKeys[key]; cur != nil && cur.state == keyManual {
		return // оператор решил, пока шла попытка
	}
	e.respKeys[key] = &k
}

// capKey — потолок: пространство (режим), правило, подсеть цели.
func capKey(space, ruleID, ip string) string {
	subnet, ok := rules.CapSubnet(ip)
	if !ok {
		subnet = ip
	}
	return space + "|" + ruleID + "|" + subnet
}

// capAcquire — место ключа в потолке. Своё место в окне — переиспользуется
// (fresh=false); иначе — новое, если в окне меньше limit мест.
func (e *engine) capAcquire(ck, key string, now time.Time, window time.Duration, limit int) (ok, fresh bool) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	slots := e.respSlots[ck]
	if slots == nil {
		slots = map[string]time.Time{}
		e.respSlots[ck] = slots
	}
	for k, at := range slots {
		if !at.After(now.Add(-window)) {
			delete(slots, k)
		}
	}
	if _, mine := slots[key]; mine {
		return true, false
	}
	if len(slots) >= limit {
		return false, false
	}
	slots[key] = now
	return true, true
}

// capRelease — владелец отдаёт место: блока по ключу нет.
func (e *engine) capRelease(ck, key string) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	if slots := e.respSlots[ck]; slots != nil {
		delete(slots, key)
		if len(slots) == 0 {
			delete(e.respSlots, ck)
		}
	}
}

// capRestore — место ключа по времени последней записи журнала (рестарт).
func (e *engine) capRestore(ck, key string, at time.Time) {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	slots := e.respSlots[ck]
	if slots == nil {
		slots = map[string]time.Time{}
		e.respSlots[ck] = slots
	}
	slots[key] = at
}

// keyRow — строка журнала по ключу.
func keyRow(ts, mode string, k respKey, step string, res respond.Result) store.ResponseRow {
	if res.IP == "" {
		res.IP = k.ip
	}
	if res.Incident == "" {
		res.Incident = k.incident
	}
	row := respRow(ts, mode, "argus-engine", res, k.ruleID, k.reason)
	row.Step = step
	return row
}

// attemptKey — одна попытка по ключу (первая или повтор): см. шапку файла. now —
// время попытки; строки итога возвращаются, резерв пишется сразу.
func (e *engine) attemptKey(ctx context.Context, base respKey, now time.Time) (rows []store.ResponseRow) {
	key := keyOf(base.incident, base.ip)
	if !e.beginFlight(key) {
		return nil // владелец — другой вызов; он и решит
	}
	defer e.endFlight(key)
	k := base
	if cur := e.keySnapshot(key); cur != nil {
		if terminal(cur.state) {
			return nil
		}
		if cur.state == keyReserveFailed && now.Sub(cur.at) < reserveRetry {
			return nil
		}
		if cur.state == keyFailed && cur.next.After(now) {
			return nil // повтор — по расписанию
		}
		k.attempts, k.slotSpace = cur.attempts, cur.slotSpace
	}
	ts := model.FormatTS(now)[:19]
	mode, _ := e.resp.Mode() // снимок режима — один на всю попытку
	set := func(state string) {
		k.state, k.at = state, now
		e.storeKey(key, k)
	}
	if mode == respond.ModeIDS {
		if k.state == keyFailed || k.attempts > 0 {
			return nil // повтор ждёт возврата в ips, решение не меняется
		}
		set(keyIDS)
		return append(rows, keyRow(ts, mode, k, stepIDS, respond.Result{Executor: "argus", OK: true, Detail: "режим IDS: автоответ выключен"}))
	}
	if k.attempts > 0 && mode != respond.ModeIPS {
		return nil // повтор неудачного блока — только в ips
	}
	if err := e.resp.Check(k.ip); err != nil {
		set(keyRefused)
		return append(rows, keyRow(ts, mode, k, stepRefused, respond.Result{Executor: "argus", OK: true, Detail: err.Error()}))
	}
	r := e.ruleFor(k.ruleID)
	limit, window := rules.DefaultBlockCap, rules.DefaultBlockCapWindow
	if r != nil {
		limit, window = r.RespondCap()
	}
	ck := capKey(mode, k.ruleID, k.ip)
	ok, _ := e.capAcquire(ck, key, now, window, limit)
	if !ok {
		set(keyCapped)
		slog.Warn("ips: потолок блокировок подсети", "incident", k.incident, "rule", k.ruleID, "ip", k.ip, "limit", limit)
		return append(rows, keyRow(ts, mode, k, stepCapped, respond.Result{Executor: "argus", OK: true,
			Detail: fmt.Sprintf("потолок блокировок: %d новых адресов подсети за %s (respond.block_cap) — адрес не заблокирован, решение за аналитиком", limit, window)}))
	}
	k.slotSpace = mode
	release := func() { e.capRelease(ck, key) }
	reserve := func() error {
		row := keyRow(ts, mode, k, stepReserve, respond.Result{Executor: "argus", OK: true, Detail: "резерв: блок адреса перед вызовом исполнителей"})
		return e.ch.InsertResponses(ctx, []store.ResponseRow{row})
	}
	results, outcome, err := e.resp.Attempt(ctx, mode, k.ip, k.incident, k.reason, k.ttl, reserve)
	if err != nil && outcome != respond.OutcomeReserveFailed {
		// обратный канал не настроен — решение без блока, места не держит
		release()
		set(keyRefused)
		return append(rows, keyRow(ts, mode, k, stepRefused, respond.Result{Executor: "argus", OK: true, Detail: err.Error()}))
	}
	step := ""
	switch outcome {
	case respond.OutcomeReserveFailed:
		release()
		set(keyReserveFailed)
		slog.Warn("ips: резерв в response_log не записан — адрес не блокируется до следующей попытки", "incident", k.incident, "ip", k.ip, "err", err)
		return nil
	case respond.OutcomeRefused:
		release()
		set(keyRefused)
		step = stepRefused
	case respond.OutcomeNoop:
		release() // уже заблокирован другим инцидентом или оператором
		set(keyDone)
		step = stepNoop
		slog.Info("ips: уже заблокирован", "ip", k.ip, "incident", k.incident, "rule", k.ruleID, "detail", results[0].Detail)
	case respond.OutcomeSimulated:
		set(keyDone)
		step = stepSimulated
		e.m.simulatedBlocks.Add(1)
	case respond.OutcomeBlocked:
		set(keyDone)
		step = stepBlocked
		e.m.autoBlocks.Add(1)
		slog.Warn("ips: заблокирован", "ip", k.ip, "incident", k.incident, "rule", k.ruleID, "attempt", k.attempts+1)
	case respond.OutcomeFailed:
		// место держится за ключом: повтор — тем же путём, по расписанию
		k.attempts++
		e.m.blockFailures.Add(1)
		if k.attempts >= respond.MaxAttempts {
			set(keyExhausted)
			step = stepExhausted
			results = append(results, respond.Result{Executor: "argus", OK: false, Detail: "все исполнители отказали, попытки исчерпаны — заблокируйте вручную"})
		} else {
			k.next = now.Add(respond.RetryDelay(k.attempts))
			set(keyFailed)
			step = stepFailed
			results = append(results, respond.Result{Executor: "argus", OK: false, Detail: fmt.Sprintf("все исполнители отказали — повтор №%d в %s", k.attempts, k.next.Format("15:04:05"))})
		}
		slog.Error("ips: блокировка не выполнена", "ip", k.ip, "incident", k.incident, "rule", k.ruleID, "attempt", k.attempts)
	}
	for _, res := range results {
		rows = append(rows, keyRow(ts, mode, k, step, res))
	}
	return rows
}

// retryKeys — повторы неудачных блоков и незаписанных резервов: тем же путём.
func (e *engine) retryKeys(ctx context.Context, now time.Time) []store.ResponseRow {
	e.respMu.Lock()
	var due []respKey
	for _, k := range e.respKeys {
		switch {
		case k.state == keyFailed && !k.next.After(now):
			due = append(due, *k)
		case k.state == keyReserveFailed && now.Sub(k.at) >= reserveRetry:
			due = append(due, *k)
		}
	}
	e.respMu.Unlock()
	var rows []store.ResponseRow
	for _, k := range due {
		rows = append(rows, e.attemptKey(ctx, k, now)...)
	}
	return rows
}

// stepPriority — какая строка последней секунды определяет состояние: итог
// главнее резерва, блок главнее отказа, решение оператора главнее всего.
var stepPriority = []string{stepManual, stepBlocked, stepExhausted, stepFailed, stepNoop, stepSimulated, stepCapped, stepRefused, stepIDS, stepReserve}

// respRetention — сколько хранить и читать решения: не меньше respStateTTL и не
// меньше самого длинного окна потолка среди правил (block_cap_window может быть
// длиннее 48 ч — место не должно теряться ни при чистке, ни при рестарте).
func (e *engine) respRetention() time.Duration {
	keep := respStateTTL
	for _, r := range e.current() {
		if r.Respond == nil {
			continue
		}
		if _, w := r.RespondCap(); w > keep {
			keep = w
		}
	}
	return keep
}

// restoreKeys — решения по ключам и места в потолке из журнала (рестарт).
// Состояние определяет только ПОСЛЕДНЯЯ запись ключа (при равном ts — по
// stepPriority), место — по её времени, число попыток — по числу неудачных
// попыток ключа в журнале. Восстановление одно на движок (respRestoreMu): два
// цикла expireBlocks после неудачного стартового чтения не применяют журнал
// дважды, и запоздавший ответ не перезаписывает свежее локальное состояние —
// ключи и места, уже известные в памяти, журнал не трогает. Журнал не прочитан —
// false: новых блоков нет, пока чтение не удастся (повтор — на каждом цикле).
func (e *engine) restoreKeys(ctx context.Context, now time.Time) bool {
	e.respRestoreMu.Lock()
	defer e.respRestoreMu.Unlock()
	return e.restoreKeysLocked(ctx, now)
}

func (e *engine) restoreKeysLocked(ctx context.Context, now time.Time) bool {
	e.respMu.Lock()
	done := e.respRestored
	e.respMu.Unlock()
	if done {
		return true
	}
	rows, err := e.ch.ResponsesSince(ctx, now.Add(-e.respRetention()))
	if err != nil {
		slog.Warn("ips: решения автоответа не восстановлены из response_log — новые блокировки отложены до чтения журнала", "err", err)
		return false
	}
	type last struct {
		at       time.Time
		rows     []store.ResponseRow // строки с ts == at
		failures int                 // неудачных попыток ключа (по сводной строке argus)
	}
	byKey := map[string]*last{}
	for _, row := range rows {
		ip, ok := respond.CanonicalIP(row.IP)
		if !ok {
			continue
		}
		key := keyOf(row.IncidentID, ip)
		at, perr := time.ParseInLocation("2006-01-02 15:04:05", row.TS, time.UTC)
		if perr != nil {
			continue
		}
		row.IP = ip
		l := byKey[key]
		switch {
		case l == nil:
			l = &last{at: at, rows: []store.ResponseRow{row}}
			byKey[key] = l
		case at.After(l.at):
			l.at, l.rows = at, []store.ResponseRow{row}
		case at.Equal(l.at):
			l.rows = append(l.rows, row)
		}
		// У каждой неудачной попытки — одна сводная строка argus с шагом failed/exhausted.
		if row.Executor == "argus" && (row.Step == stepFailed || row.Step == stepExhausted) {
			l.failures++
		}
	}
	doubtful := 0
	e.respMu.Lock()
	for key, l := range byKey {
		if _, known := e.respKeys[key]; known {
			continue // свежее локальное состояние главнее журнала
		}
		var row store.ResponseRow
	pick:
		for _, step := range stepPriority {
			for _, r := range l.rows {
				if r.Step == step {
					row = r
					break pick
				}
			}
		}
		if row.Step == "" {
			continue
		}
		k := &respKey{incident: row.IncidentID, ip: row.IP, ruleID: row.RuleID, reason: row.Reason, at: l.at, slotSpace: row.Mode}
		if r := e.ruleFor(row.RuleID); r != nil && r.Respond != nil {
			k.ttl, _ = time.ParseDuration(r.Respond.TTL)
		}
		holdsSlot := false
		switch row.Step {
		case stepReserve:
			// Резерв без итога: исполнитель мог заблокировать, итог не записался.
			k.state, holdsSlot = keyDone, true
			doubtful++
		case stepBlocked, stepSimulated:
			k.state, holdsSlot = keyDone, true
		case stepNoop:
			k.state = keyDone
		case stepFailed:
			// повтор — по прежнему расписанию от времени последней неудачи; место — то же
			k.state, holdsSlot = keyFailed, true
			k.attempts = max(l.failures, 1)
			if k.attempts >= respond.MaxAttempts {
				k.state = keyExhausted
			} else {
				k.next = l.at.Add(respond.RetryDelay(k.attempts))
			}
		case stepExhausted:
			k.state, k.attempts, holdsSlot = keyExhausted, respond.MaxAttempts, true
		case stepCapped:
			k.state = keyCapped
		case stepRefused:
			k.state = keyRefused
		case stepIDS:
			k.state = keyIDS
		case stepManual:
			k.state = keyManual
		default:
			continue
		}
		e.respKeys[key] = k
		if holdsSlot {
			ck := capKey(row.Mode, row.RuleID, row.IP)
			slots := e.respSlots[ck]
			if slots == nil {
				slots = map[string]time.Time{}
				e.respSlots[ck] = slots
			}
			if _, known := slots[key]; !known {
				slots[key] = l.at
			}
		}
	}
	e.respRestored = true
	e.respMu.Unlock()
	if doubtful > 0 {
		slog.Warn("ips: резерв блока без итога в response_log — адрес считается заблокированным, место занято; проверьте NGFW", "addresses", doubtful)
	}
	return true
}

// respReady — журнал прочитан; иначе — ещё одна попытка чтения.
func (e *engine) respReady(ctx context.Context, now time.Time) bool {
	return e.respReadyOrDefer(ctx, now, nil)
}

// respDeferredMax — сколько инцидентов ждут чтения журнала: сверх — самые старые
// отбрасываются с предупреждением (их адреса не блокируются, решение за аналитиком).
const respDeferredMax = 10000

// respReadyOrDefer — журнал прочитан; иначе инциденты incs откладываются до чтения.
// Откладывание — под тем же замком, что и чтение: восстановление в expireBlocks
// не может проскочить между неудачным чтением и записью в очередь, и отложенный
// инцидент не теряется, даже если его события больше не приходят.
func (e *engine) respReadyOrDefer(ctx context.Context, now time.Time, incs []*incidents.Incident) bool {
	e.respRestoreMu.Lock()
	defer e.respRestoreMu.Unlock()
	if e.restoreKeysLocked(ctx, now) {
		return true
	}
	if len(incs) == 0 {
		return false
	}
	e.respMu.Lock()
	defer e.respMu.Unlock()
	for _, inc := range incs {
		if _, queued := e.respDeferred[inc.IncidentID]; !queued {
			e.respDeferredOrder = append(e.respDeferredOrder, inc.IncidentID)
		}
		e.respDeferred[inc.IncidentID] = inc
	}
	if drop := len(e.respDeferredOrder) - respDeferredMax; drop > 0 {
		for _, id := range e.respDeferredOrder[:drop] {
			delete(e.respDeferred, id)
		}
		e.respDeferredOrder = append([]string(nil), e.respDeferredOrder[drop:]...)
		slog.Warn("ips: очередь отложенных до чтения журнала инцидентов переполнена — старые отброшены", "dropped", drop)
	}
	return false
}

// takeDeferred — отложенные инциденты в порядке поступления (очередь очищается).
func (e *engine) takeDeferred() []*incidents.Incident {
	e.respMu.Lock()
	defer e.respMu.Unlock()
	out := make([]*incidents.Incident, 0, len(e.respDeferredOrder))
	for _, id := range e.respDeferredOrder {
		if inc := e.respDeferred[id]; inc != nil {
			out = append(out, inc)
		}
	}
	e.respDeferred, e.respDeferredOrder = map[string]*incidents.Incident{}, nil
	return out
}

// operatorOverride — ручная блокировка или снятие адреса: все ключи адреса
// переходят в конечное «решение оператора» (с записью в журнал, чтобы пережить
// рестарт) и отдают места; автоповтор их больше не трогает. Возвращает строки
// журнала и число ключей, по которым ещё ждала автоблокировка.
func (e *engine) operatorOverride(ip, actor, reason string, now time.Time) (rows []store.ResponseRow, pending int) {
	ip, ok := respond.CanonicalIP(ip)
	if !ok {
		return nil, 0
	}
	ts := model.FormatTS(now)[:19]
	e.respMu.Lock()
	defer e.respMu.Unlock()
	for key, k := range e.respKeys {
		if k.ip != ip || k.state == keyManual {
			continue
		}
		if !terminal(k.state) {
			pending++
		}
		if k.slotSpace != "" {
			ck := capKey(k.slotSpace, k.ruleID, k.ip)
			if slots := e.respSlots[ck]; slots != nil {
				delete(slots, key)
			}
		}
		k.state, k.at = keyManual, now
		row := respRow(ts, "manual", actor, respond.Result{Executor: "argus", OK: true, IP: ip, Incident: k.incident,
			Detail: "решение оператора: автоблокировка адреса по инциденту отменена"}, k.ruleID, reason)
		row.Step = stepManual
		rows = append(rows, row)
	}
	return rows, pending
}

// pruneKeysLocked — конечные ключи старше ttl и места старше окна хранения.
func (e *engine) pruneKeysLocked(now time.Time, ttl time.Duration) {
	for key, k := range e.respKeys {
		if terminal(k.state) && now.Sub(k.at) > ttl {
			delete(e.respKeys, key)
		}
	}
	keep := max(ttl, e.respRetention())
	for ck, slots := range e.respSlots {
		for key, at := range slots {
			if now.Sub(at) > keep {
				delete(slots, key)
			}
		}
		if len(slots) == 0 {
			delete(e.respSlots, ck)
		}
	}
}
