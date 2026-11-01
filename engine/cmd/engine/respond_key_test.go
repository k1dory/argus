package main

// Автомат блокировки адреса (respond_key.go) для обычных инцидентов: потолок
// подсети, запись вперёд, единственный владелец ключа, повтор тем же путём,
// восстановление по последней записи журнала. Сценарии — тесты codex раундов 3–5
// к #49 (ветка engine-respond-cap-wal-r5-tests), перенесённые со склеенных
// инцидентов на обычные: в main склейки нет, автомат — у всех инцидентов.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/incidents"
	"github.com/devitex-soft/argus/engine/internal/model"
	"github.com/devitex-soft/argus/engine/internal/respond"
	"github.com/devitex-soft/argus/engine/internal/store"
)

func capRule(limit int) string {
	return fmt.Sprintf(`
title: WAF RCE
id: t-waf
level: critical
detection:
  selection: {source.class: waf, action: http.attack}
  condition: selection
dedupe: 30m
respond: {action: block_ip, target: src.ip, min_level: critical, ttl: 1h, min_events: 1, max_targets: 10, block_cap: %d, block_cap_window: 1h}
`, limit)
}

// keyExecutor — исполнитель с выключателем и необязательным затвором на /block.
type keyExecutor struct {
	srv       *httptest.Server
	available atomic.Bool
	blocks    atomic.Int32
	calls     atomic.Int32
	gate      chan struct{} // не nil — /block ждёт закрытия
	entered   chan struct{}
}

func newKeyExecutor(t *testing.T) *keyExecutor {
	t.Helper()
	x := &keyExecutor{}
	x.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/block" {
			return
		}
		x.calls.Add(1)
		if x.entered != nil {
			select {
			case x.entered <- struct{}{}:
			default:
			}
		}
		if x.gate != nil {
			<-x.gate
		}
		if !x.available.Load() {
			http.Error(w, "fixture executor unavailable", http.StatusServiceUnavailable)
			return
		}
		x.blocks.Add(1)
	}))
	t.Cleanup(x.srv.Close)
	return x
}

func keyEngine(t *testing.T, f *fakeCH, x *keyExecutor, limit int) *engine {
	t.Helper()
	return testEngine(t, f, rulesDirWith(t, map[string]string{"r.yml": capRule(limit)}), ipsConfig(x.srv), "s", "s")
}

func capInc(id string, ips ...string) *incidents.Incident {
	inc := &incidents.Incident{IncidentID: id, RuleID: "t-waf", RuleTitle: "WAF RCE", Level: "critical"}
	for i, ip := range ips {
		inc.Events = append(inc.Events, wafEvent(fmt.Sprintf("2026-09-10 10:00:%02d.000", i), ip, "file", ""))
	}
	inc.EventCount = uint32(len(inc.Events))
	return inc
}

// saveJournal — строки response_log с шагом как ответ ResponsesSince: так их
// прочитает движок после рестарта.
func saveJournal(f *fakeCH) {
	var rows []string
	for _, r := range f.rows("response_log") {
		if !strings.Contains(r, `"step":""`) {
			rows = append(rows, r)
		}
	}
	f.mu.Lock()
	f.selects["FROM response_log WHERE ip != ''"] = strings.Join(rows, "\n") + "\n"
	f.mu.Unlock()
}

func setFail(f *fakeCH, table string, fail bool) {
	f.mu.Lock()
	f.fail[table] = fail
	f.mu.Unlock()
}

func keyState(e *engine, incident, ip string) string {
	if k := e.keySnapshot(keyOf(incident, ip)); k != nil {
		return k.state
	}
	return ""
}

func countSteps(f *fakeCH, step string) int {
	n := 0
	for _, r := range f.rows("response_log") {
		if strings.Contains(r, `"step":"`+step+`"`) {
			n++
		}
	}
	return n
}

// Потолок — на правило и подсеть: третий адрес /24 при block_cap=2 — «потолок»,
// адрес другой /24 блокируется; у simulate потолок свой.
func TestRespondKeyCapPerSubnet(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 2)
	ctx, now := context.Background(), time.Now()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.1"), capInc("INC-2", "203.0.113.2"), capInc("INC-3", "203.0.113.3"), capInc("INC-4", "198.51.100.4")}, now)
	if got := x.blocks.Load(); got != 3 {
		t.Fatalf("блоков %d, ожидалось 3 (два в 203.0.113.0/24 и один в соседней)", got)
	}
	if keyState(e, "INC-3", "203.0.113.3") != keyCapped || countSteps(f, stepCapped) != 1 {
		t.Fatalf("третий адрес подсети: %q", keyState(e, "INC-3", "203.0.113.3"))
	}
	if countSteps(f, stepReserve) != 3 {
		t.Fatalf("резерв — перед каждым вызовом исполнителя: %d", countSteps(f, stepReserve))
	}
	e.resp.SetMode(respond.ModeSimulate)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-5", "203.0.113.5")}, now)
	if keyState(e, "INC-5", "203.0.113.5") != keyDone || countSteps(f, stepSimulated) == 0 || x.calls.Load() != 3 {
		t.Fatal("simulate: свой потолок, исполнитель не вызывается")
	}
}

// Раунд 5: повтор после выхода места из окна занимает текущее место или
// получает потолок — не блокирует сверх block_cap.
func TestRespondKeyRetryCannotBypassExpiredCapSlot(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 1)
	ctx, t0 := context.Background(), time.Now()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	if keyState(e, "INC-1", "203.0.113.7") != keyFailed || x.blocks.Load() != 0 {
		t.Fatal("фикстура: отказ исполнителя держит единственное место")
	}
	e.resp.SetMode(respond.ModeIDS)
	t1 := t0.Add(61 * time.Minute)
	if rows := e.retryKeys(ctx, t1); len(rows) != 0 || keyState(e, "INC-1", "203.0.113.7") != keyFailed {
		t.Fatal("в IDS повтор ждёт, решение не меняется")
	}
	e.resp.SetMode(respond.ModeIPS)
	x.available.Store(true)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, t1)
	if x.blocks.Load() != 1 {
		t.Fatal("фикстура: второй адрес занимает текущее место")
	}
	e.expireBlocks(ctx, t1.Add(time.Second))
	if got := x.blocks.Load(); got != 1 || keyState(e, "INC-1", "203.0.113.7") != keyCapped {
		t.Fatalf("повтор обошёл потолок: блоков %d при block_cap=1, состояние %q", got, keyState(e, "INC-1", "203.0.113.7"))
	}
}

// Раунд 5: адрес из события — строка; ::ffff:… и запись IPv6 с нулями — тот же
// ключ, и повтор так же требует резерв.
func TestRespondKeyCanonicalRetryStillRequiresReserve(t *testing.T) {
	for raw, canon := range map[string]string{"::ffff:203.0.113.7": "203.0.113.7", "2001:0DB8:0001:0000:0000:0000:0000:0007": "2001:db8:1::7"} {
		t.Run(raw, func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			e := keyEngine(t, f, x, 4)
			ctx, t0 := context.Background(), time.Now()
			e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", raw)}, t0)
			if keyState(e, "INC-1", canon) != keyFailed || keyState(e, "INC-1", raw) != "" {
				t.Fatalf("ключ — в канонической записи %s", canon)
			}
			setFail(f, "response_log", true)
			x.available.Store(true)
			e.expireBlocks(ctx, t0.Add(61*time.Second))
			if got := x.blocks.Load(); got != 0 || keyState(e, "INC-1", canon) != keyReserveFailed {
				t.Fatalf("повтор без резерва: блоков %d, состояние %q", got, keyState(e, "INC-1", canon))
			}
			setFail(f, "response_log", false)
			e.expireBlocks(ctx, t0.Add(2*time.Minute+time.Second))
			if x.blocks.Load() != 1 {
				t.Fatal("после восстановления журнала повтор блокирует")
			}
		})
	}
}

// Раунд 4: резерв не записан — исполнитель не вызывается, ни в первой попытке, ни в повторе.
func TestRespondKeyRetryRequiresDurableReserve(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	ctx, t0 := context.Background(), time.Now()
	setFail(f, "response_log", true)
	x.available.Store(true)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	if x.calls.Load() != 0 || keyState(e, "INC-1", "203.0.113.7") != keyReserveFailed {
		t.Fatal("первая попытка без резерва вызвала исполнителя")
	}
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0.Add(10*time.Second))
	e.expireBlocks(ctx, t0.Add(30*time.Second))
	if x.calls.Load() != 0 {
		t.Fatal("до паузы reserveRetry новой попытки нет")
	}
	e.expireBlocks(ctx, t0.Add(61*time.Second))
	if x.calls.Load() != 0 {
		t.Fatal("журнал всё ещё недоступен — исполнитель не вызывается")
	}
	setFail(f, "response_log", false)
	e.expireBlocks(ctx, t0.Add(2*time.Minute+time.Second))
	if x.blocks.Load() != 1 || keyState(e, "INC-1", "203.0.113.7") != keyDone {
		t.Fatal("журнал доступен — блок с резервом")
	}
}

// Раунд 4: попытка держит владение ключом, пока пишется резерв: второй вызов по
// тому же ключу ничего не трогает — ни места, ни состояния — при успехе и при
// отказе INSERT.
func TestRespondKeyOverlappingAttemptCannotTouchOwner(t *testing.T) {
	for _, reserveOK := range []bool{true, false} {
		t.Run(fmt.Sprintf("reserve_ok=%v", reserveOK), func(t *testing.T) {
			f := newFakeCH(t)
			x := newKeyExecutor(t)
			x.available.Store(true)
			release, entered := make(chan struct{}), make(chan struct{}, 1)
			journal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Query().Get("query"), "INSERT INTO response_log") {
					entered <- struct{}{}
					<-release
					if !reserveOK {
						http.Error(w, "Code: 243. DB::Exception: fixture", http.StatusInternalServerError)
						return
					}
				}
				f.srv.Config.Handler.ServeHTTP(w, r)
			}))
			t.Cleanup(journal.Close)
			e := keyEngine(t, f, x, 1)
			e.ch = store.New(journal.URL, "argus", "default", "")
			ctx, now := context.Background(), time.Now()
			base := respKey{incident: "INC-1", ip: "203.0.113.7", ruleID: "t-waf", reason: "WAF RCE (t-waf)", ttl: time.Hour}
			done := make(chan []store.ResponseRow)
			go func() { done <- e.attemptKey(ctx, base, now) }()
			<-entered
			if rows := e.attemptKey(ctx, base, now.Add(time.Second)); rows != nil || x.calls.Load() != 0 {
				t.Fatal("второй вызов при занятом владельце что-то сделал")
			}
			close(release)
			<-done
			key := keyOf("INC-1", "203.0.113.7")
			e.respMu.Lock()
			slots := len(e.respSlots[capKey(respond.ModeIPS, "t-waf", "203.0.113.7")])
			_, owned := e.respSlots[capKey(respond.ModeIPS, "t-waf", "203.0.113.7")][key]
			e.respMu.Unlock()
			if reserveOK && (x.blocks.Load() != 1 || !owned || slots != 1) {
				t.Fatalf("успех: блок %d, место ключа %v, мест %d", x.blocks.Load(), owned, slots)
			}
			if !reserveOK && (x.calls.Load() != 0 || slots != 0 || keyState(e, "INC-1", "203.0.113.7") != keyReserveFailed) {
				t.Fatalf("резерв не записан: вызовов %d, мест %d, состояние %q", x.calls.Load(), slots, keyState(e, "INC-1", "203.0.113.7"))
			}
		})
	}
}

// Раунд 5: два цикла повторов одновременно — второй не трогает чужую попытку,
// успешный блок первого остаётся конечным и не повторяется после TTL.
func TestRespondKeyConcurrentRetryCannotConsumeOwnersOutcome(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	ctx, t0 := context.Background(), time.Now()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	x.available.Store(true)
	x.gate, x.entered = make(chan struct{}), make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); e.expireBlocks(ctx, t0.Add(61*time.Second)) }()
	<-x.entered
	e.resp.SetMode(respond.ModeIDS)
	if rows := e.retryKeys(ctx, t0.Add(62*time.Second)); len(rows) != 0 {
		t.Fatal("второй цикл вмешался в попытку владельца")
	}
	e.resp.SetMode(respond.ModeIPS)
	close(x.gate)
	wg.Wait()
	x.gate = nil
	if keyState(e, "INC-1", "203.0.113.7") != keyDone || x.blocks.Load() != 1 {
		t.Fatalf("итог владельца: %q, блоков %d", keyState(e, "INC-1", "203.0.113.7"), x.blocks.Load())
	}
	e.expireBlocks(ctx, t0.Add(3*time.Hour))
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0.Add(3*time.Hour))
	if x.blocks.Load() != 1 {
		t.Fatal("конечный блок повторился")
	}
}

// Раунд 5: снимок режима — один на попытку. Ручная операция держит замок
// адреса, пока попытка снята в simulate; переключение в ips до получения замка
// не превращает её в блок без резерва.
func TestRespondKeySimulateSnapshotCannotSkipReserve(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	e := keyEngine(t, f, x, 4)
	e.resp.SetMode(respond.ModeSimulate)
	ctx, now := context.Background(), time.Now()
	x.gate, x.entered = make(chan struct{}), make(chan struct{}, 1)
	manual := make(chan error, 1)
	go func() { _, err := e.resp.BlockIP(ctx, "203.0.113.7", "INC-9", "оператор"); manual <- err }()
	<-x.entered // ручная блокировка держит замок адреса
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	}()
	time.Sleep(50 * time.Millisecond) // попытка сняла режим simulate и ждёт замка
	e.resp.SetMode(respond.ModeIPS)
	close(x.gate)
	<-done
	if err := <-manual; err != nil {
		t.Fatal(err)
	}
	if x.calls.Load() != 1 || countSteps(f, stepReserve) != 0 || countSteps(f, stepSimulated) == 0 {
		t.Fatalf("попытка в simulate сменила режим: вызовов %d, резервов %d", x.calls.Load(), countSteps(f, stepReserve))
	}
}

// Раунд 4–5: восстановление по последней записи ключа; место — по её времени.
func TestRespondKeyRestoreFromLastJournalRow(t *testing.T) {
	t.Run("отказ раньше резерва не разрешает третий блок", func(t *testing.T) {
		f := newFakeCH(t)
		x := newKeyExecutor(t)
		e := keyEngine(t, f, x, 4)
		ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
		// новый резерв позже отказа, итог не дошёл до журнала
		later := keyRow(model.FormatTS(t0.Add(61 * time.Second))[:19], respond.ModeIPS,
			respKey{incident: "INC-1", ip: "203.0.113.7", ruleID: "t-waf", reason: "WAF RCE (t-waf)"}, stepReserve,
			respond.Result{Executor: "argus", OK: true, Detail: "резерв"})
		if err := e.ch.InsertResponses(ctx, []store.ResponseRow{later}); err != nil {
			t.Fatal(err)
		}
		saveJournal(f)
		x.available.Store(true)
		r := keyEngine(t, f, x, 4)
		r.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0.Add(2*time.Minute))
		r.expireBlocks(ctx, t0.Add(3*time.Minute))
		if x.calls.Load() != 1 || keyState(r, "INC-1", "203.0.113.7") != keyDone {
			t.Fatalf("резерв без итога — блок мог встать: вызовов %d, состояние %q", x.calls.Load(), keyState(r, "INC-1", "203.0.113.7"))
		}
	})
	t.Run("продлённое место не подменяется истёкшим", func(t *testing.T) {
		f := newFakeCH(t)
		x := newKeyExecutor(t)
		e := keyEngine(t, f, x, 1)
		ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
		x.available.Store(true)
		t1 := t0.Add(61 * time.Minute)
		e.expireBlocks(ctx, t1) // место истекло — новое, блок
		if x.blocks.Load() != 1 {
			t.Fatal("фикстура: повтор после окна блокирует на новом месте")
		}
		saveJournal(f)
		r := keyEngine(t, f, x, 1)
		r.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, t1.Add(30*time.Minute))
		if x.blocks.Load() != 1 || keyState(r, "INC-2", "203.0.113.8") != keyCapped {
			t.Fatal("место после рестарта восстановлено по старой записи — потолок обойдён")
		}
	})
	t.Run("отказ остаётся повторяемым и при задержке повтора", func(t *testing.T) {
		f := newFakeCH(t)
		x := newKeyExecutor(t)
		e := keyEngine(t, f, x, 4)
		ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
		cycleAt := t0.Add(61 * time.Second)
		time.Sleep(1100 * time.Millisecond) // задержка горутины: резерв и итог — по времени цикла
		e.expireBlocks(ctx, cycleAt)
		if countSteps(f, stepFailed) < 4 || countSteps(f, stepReserve) != 2 {
			t.Fatalf("фикстура: две неудачные попытки с резервами: %v", f.rows("response_log"))
		}
		saveJournal(f)
		x.available.Store(true)
		r := keyEngine(t, f, x, 4)
		r.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, cycleAt.Add(time.Second))
		r.expireBlocks(ctx, cycleAt.Add(2*time.Second))
		if x.blocks.Load() != 1 {
			t.Fatalf("отказ после рестарта стал конечным: %q", keyState(r, "INC-1", "203.0.113.7"))
		}
	})
	t.Run("отказ после рестарта повторяется на своём месте при полном потолке", func(t *testing.T) {
		f := newFakeCH(t)
		x := newKeyExecutor(t)
		e := keyEngine(t, f, x, 2)
		ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
		x.available.Store(true)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, t0)
		saveJournal(f)
		r := keyEngine(t, f, x, 2)
		r.expireBlocks(ctx, t0.Add(time.Minute))
		if !r.respRestored {
			r.restoreKeys(ctx, t0.Add(time.Minute))
			r.expireBlocks(ctx, t0.Add(time.Minute))
		}
		if x.blocks.Load() != 2 || keyState(r, "INC-1", "203.0.113.7") != keyDone {
			t.Fatalf("повтор при полном потолке: блоков %d, состояние %q", x.blocks.Load(), keyState(r, "INC-1", "203.0.113.7"))
		}
	})
	t.Run("блоки закрытых инцидентов занимают потолок после рестарта", func(t *testing.T) {
		f := newFakeCH(t)
		x := newKeyExecutor(t)
		x.available.Store(true)
		e := keyEngine(t, f, x, 2)
		ctx, t0 := context.Background(), time.Now().UTC().Truncate(time.Second)
		e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7"), capInc("INC-2", "203.0.113.8")}, t0)
		saveJournal(f)
		r := keyEngine(t, f, x, 2)
		r.autoRespond(ctx, []*incidents.Incident{capInc("INC-3", "203.0.113.9")}, t0.Add(10*time.Minute))
		if x.blocks.Load() != 2 || keyState(r, "INC-3", "203.0.113.9") != keyCapped {
			t.Fatal("потолок после рестарта не учёл журнал")
		}
	})
}

// Журнал не прочитан при старте — fail-closed: новых блоков нет, инцидент не
// помечен; журнал прочитался — следующий цикл блокирует.
func TestRespondKeyUnreadJournalDefersBlocks(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	x.available.Store(true)
	f.selects["FROM response_log WHERE ip != ''"] = `{"exception":"Code: 241. DB::Exception: fixture"}` + "\n"
	e := keyEngine(t, f, x, 4)
	ctx, now := context.Background(), time.Now()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now)
	e.expireBlocks(ctx, now)
	if x.calls.Load() != 0 || e.respStatus("INC-1") != "" || len(f.rows("response_log")) != 0 {
		t.Fatal("журнал не прочитан — блокировать нельзя")
	}
	f.mu.Lock()
	f.selects["FROM response_log WHERE ip != ''"] = "\n"
	f.mu.Unlock()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, now.Add(time.Minute))
	if x.blocks.Load() != 1 {
		t.Fatal("журнал прочитан — блок")
	}
}

// Попытки исчерпаны — место держится, решение за аналитиком; режим IDS — конечное.
func TestRespondKeyExhaustedAndIDS(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 4)
	ctx, t0 := context.Background(), time.Now()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	at := t0
	for i := 1; i < respond.MaxAttempts; i++ {
		at = at.Add(respond.RetryDelay(i) + time.Second)
		e.expireBlocks(ctx, at)
	}
	if keyState(e, "INC-1", "203.0.113.7") != keyExhausted || x.calls.Load() != int32(respond.MaxAttempts) || countSteps(f, stepExhausted) == 0 {
		t.Fatalf("исчерпано: %q, вызовов %d", keyState(e, "INC-1", "203.0.113.7"), x.calls.Load())
	}
	e.expireBlocks(ctx, at.Add(time.Hour))
	if x.calls.Load() != int32(respond.MaxAttempts) {
		t.Fatal("после исчерпания попыток повторов нет")
	}
	e.resp.SetMode(respond.ModeIDS)
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, t0)
	if keyState(e, "INC-2", "203.0.113.8") != keyIDS || countSteps(f, stepIDS) != 1 {
		t.Fatal("режим IDS: конечное ids, строка ids")
	}
}

// Повтор после окна занимает место заново, с текущим временем: иначе старое
// время места истекает раньше, и соседний адрес проходит сверх потолка в том же окне.
func TestRespondKeyRetryAfterWindowRenewsSlot(t *testing.T) {
	f := newFakeCH(t)
	x := newKeyExecutor(t)
	e := keyEngine(t, f, x, 1)
	ctx, t0 := context.Background(), time.Now()
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-1", "203.0.113.7")}, t0)
	x.available.Store(true)
	t1 := t0.Add(61 * time.Minute)
	e.expireBlocks(ctx, t1)
	if x.blocks.Load() != 1 {
		t.Fatal("фикстура: повтор после окна блокирует")
	}
	e.autoRespond(ctx, []*incidents.Incident{capInc("INC-2", "203.0.113.8")}, t1.Add(time.Minute))
	if got := x.blocks.Load(); got != 1 || keyState(e, "INC-2", "203.0.113.8") != keyCapped {
		t.Fatalf("место повтора не обновлено: блоков %d за окно при block_cap=1", got)
	}
}
