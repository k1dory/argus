package sink

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// mockCH: строки с Object=="poison" ломают любой батч, где они есть (код 27);
// "heavy" — делимая ошибка 241; "timeout" — транспортная ошибка только на
// батчах с этой строкой (база жива, батч — нет).
type mockCH struct {
	mu          sync.Mutex
	inserted    [][]any
	rejects     []Reject
	down        bool // транспортная ошибка на всё
	calls       int
	rejectCalls int
	noTable     bool
}

func (m *mockCH) InsertEvents(_ context.Context, rows []any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	if m.down {
		return errors.New("clickhouse events: dial tcp: connection refused")
	}
	for _, r := range rows {
		switch r.(model.Event).Object {
		case "poison":
			return &Error{Table: "events", Status: 400, Code: 27, Msg: "Code: 27. DB::Exception: Cannot parse input: expected ',' before: 'x'"}
		case "heavy":
			return &Error{Table: "events", Status: 500, Code: 241, Msg: "Code: 241. DB::Exception: Memory limit exceeded"}
		case "timeout":
			return errors.New("clickhouse events: context deadline exceeded (Client.Timeout)")
		}
	}
	cp := make([]any, len(rows))
	copy(cp, rows)
	m.inserted = append(m.inserted, cp)
	return nil
}

func (m *mockCH) InsertRejects(_ context.Context, rows []Reject) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectCalls++
	if m.noTable {
		return &Error{Table: "ingest_rejects", Status: 404, Code: 60, Msg: "Code: 60. DB::Exception: Table argus.ingest_rejects does not exist"}
	}
	m.rejects = append(m.rejects, rows...)
	return nil
}

func (m *mockCH) rows() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, b := range m.inserted {
		n += len(b)
	}
	return n
}

func newTestWriter(m *mockCH) (*Writer, *Stats) {
	st := &Stats{}
	w := NewWriter(m, NewQueue(1000, st), st)
	w.Backoff, w.MaxBackoff = time.Millisecond, 2*time.Millisecond
	return w, st
}

func ev(obj string) model.Event {
	return model.Event{Source: "test", Object: obj, TS: "2026-09-14 12:00:00.000"}
}

func TestPoisonRowBisected(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	w.Write(context.Background(), []any{ev("a"), ev("poison"), ev("b")})
	if got := m.rows(); got != 2 {
		t.Fatalf("вставлено %d строк, want 2: %v", got, m.inserted)
	}
	if len(m.rejects) != 1 || m.rejects[0].Source != "test" || m.rejects[0].Reason == "" {
		t.Fatalf("rejects: %+v", m.rejects)
	}
	if m.rejects[0].Raw == "" || m.rejects[0].Raw[0] != '{' {
		t.Errorf("raw должен быть JSON строки: %q", m.rejects[0].Raw)
	}
	if st.DeadLetter.Load() != 1 || st.Inserted.Load() != 2 {
		t.Errorf("stats: dead=%d ins=%d", st.DeadLetter.Load(), st.Inserted.Load())
	}
}

func TestPoisonManyAndNoRejectsTable(t *testing.T) {
	m := &mockCH{noTable: true}
	w, st := newTestWriter(m)
	batch := make([]any, 0, 100)
	for i := 0; i < 100; i++ {
		if i%7 == 0 {
			batch = append(batch, ev("poison"))
		} else {
			batch = append(batch, ev("ok"))
		}
	}
	w.Write(context.Background(), batch)
	// бисекция до строк: 15 ядовитых (каждая 7-я) отвергнуты, 85 корректных вставлены;
	// таблицы отказов нет — ядовитые строки (в очереди в памяти) отбрасываются.
	if m.rows() != 85 || st.DeadLetter.Load() != 15 {
		t.Fatalf("rows=%d dead=%d", m.rows(), st.DeadLetter.Load())
	}
	// отказы копятся и пишутся одним INSERT на батч
	if st.RejectsFailed.Load() != 15 || m.rejectCalls != 1 {
		t.Errorf("RejectsFailed=%d rejectCalls=%d", st.RejectsFailed.Load(), m.rejectCalls)
	}
}

// Бисекция до строк и при ядовитых данных во всех строках: 8 строк — батч, 2, 4, 8
// частей (15 вставок), отказы — одним INSERT на 8 строк. Это цена того, что ядовитая
// строка не уносит корректных соседей (ревью codex #43).
func TestBisectCapBothHalvesRejected(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	batch := make([]any, 0, 8)
	for i := 0; i < 8; i++ {
		batch = append(batch, ev("poison"))
	}
	w.Write(context.Background(), batch)
	if m.calls != 15 {
		t.Errorf("InsertEvents вызван %d раз, want 15 (1+2+4+8)", m.calls)
	}
	if m.rejectCalls != 1 || len(m.rejects) != 8 || st.DeadLetter.Load() != 8 {
		t.Errorf("rejectCalls=%d rejects=%d dead=%d", m.rejectCalls, len(m.rejects), st.DeadLetter.Load())
	}
	// одна ядовитая строка в хвосте: бисекция доходит до неё, остальное вставлено
	m = &mockCH{}
	w, st = newTestWriter(m)
	batch = batch[:0]
	for i := 0; i < 7; i++ {
		batch = append(batch, ev("ok"))
	}
	batch = append(batch, ev("poison"))
	w.Write(context.Background(), batch)
	if m.rows() != 7 || st.DeadLetter.Load() != 1 || len(m.rejects) != 1 {
		t.Errorf("rows=%d dead=%d rejects=%d", m.rows(), st.DeadLetter.Load(), len(m.rejects))
	}
	if m.calls > 8 {
		t.Errorf("бисекция одной строки из 8: %d вызовов, ожидалось ≤ 8", m.calls)
	}
}

// Делимая ошибка (241 Memory limit) — не транспорт: батч делится, а не крутится в pending вечно.
func TestDivisibleErrorBisected(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	w.Write(context.Background(), []any{ev("a"), ev("b"), ev("c"), ev("heavy")})
	if m.rows() != 3 || st.DeadLetter.Load() != 1 || st.Requeued.Load() != 0 || w.Queue.Rows() != 0 {
		t.Fatalf("rows=%d dead=%d requeued=%d pending=%d", m.rows(), st.DeadLetter.Load(), st.Requeued.Load(), w.Queue.Rows())
	}
	if m.rejects[0].Reason == "" || !strings.Contains(m.rejects[0].Reason, "241") {
		t.Errorf("reason: %q", m.rejects[0].Reason)
	}
}

// Транспортный отказ одного батча при живой базе: три возврата в pending, потом целиком в rejects.
func TestRequeueLimitWhileClickHouseAlive(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	w.Attempts = 1
	bad := []any{ev("timeout"), ev("x")}
	w.Queue.Push(bad)
	for cycle := 1; cycle <= MaxRequeues; cycle++ {
		w.Write(context.Background(), []any{ev("other")}) // база жива: другие батчи проходят
		b, ok := w.Queue.Pop()
		if !ok {
			t.Fatalf("цикл %d: очередь пуста", cycle)
		}
		w.WriteBatch(context.Background(), b)
		if cycle < MaxRequeues && (w.Queue.Rows() != 2 || st.DeadLetter.Load() != 0) {
			t.Fatalf("цикл %d: pending=%d dead=%d", cycle, w.Queue.Rows(), st.DeadLetter.Load())
		}
	}
	if st.DeadLetter.Load() != 2 || len(m.rejects) != 2 || w.Queue.Rows() != 0 || st.Requeued.Load() != MaxRequeues-1 {
		t.Errorf("dead=%d rejects=%d pending=%d requeued=%d", st.DeadLetter.Load(), len(m.rejects), w.Queue.Rows(), st.Requeued.Load())
	}
	// база лежит для всех: счётчик не растёт, батч не теряется
	m = &mockCH{down: true}
	w, st = newTestWriter(m)
	w.Attempts = 1
	w.Queue.Push([]any{ev("a")})
	for cycle := 0; cycle < MaxRequeues+2; cycle++ {
		b, _ := w.Queue.Pop()
		w.WriteBatch(context.Background(), b)
	}
	if st.DeadLetter.Load() != 0 || w.Queue.Rows() != 1 {
		t.Errorf("при мёртвой базе батч ушёл в dead-letter: dead=%d pending=%d", st.DeadLetter.Load(), w.Queue.Rows())
	}
}

// Остановка: ctx писателей отменён, батчер делает последний Push и Close —
// строка должна быть вставлена, писатели завершиться по Close, а не по ctx.
func TestShutdownFlushesFinalBatch(t *testing.T) {
	m := &mockCH{}
	st := &Stats{}
	q := NewQueue(1000, st)
	ctx, cancel := context.WithCancel(context.Background())
	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		w := NewWriter(m, q, st)
		writers.Add(1)
		go func() { defer writers.Done(); w.Run(ctx) }()
	}
	cancel() // сигнал остановки пришёл раньше финального flush
	q.Push([]any{ev("last")})
	q.Close()
	writers.Wait()
	if st.Inserted.Load() != 1 || q.Rows() != 0 || m.rows() != 1 {
		t.Fatalf("inserted=%d pending=%d rows=%d", st.Inserted.Load(), q.Rows(), m.rows())
	}
}

func TestQueueBytesCap(t *testing.T) {
	st := &Stats{}
	big := func(n int) model.Event { return model.Event{Source: "t", Raw: strings.Repeat("x", n)} }
	q := NewQueueBytes(1000, 3000, st)
	q.Push([]any{big(1000)})
	q.Push([]any{big(1000)})
	if q.Bytes() < 2000 || st.PendingDropped.Load() != 0 {
		t.Fatalf("bytes=%d dropped=%d", q.Bytes(), st.PendingDropped.Load())
	}
	q.Push([]any{big(1000)}) // ~3700 > 3000 → старейший выброшен
	if st.PendingDropped.Load() != 1 || q.Bytes() > 3000 {
		t.Errorf("bytes=%d dropped=%d", q.Bytes(), st.PendingDropped.Load())
	}
	b, _ := q.Pop()
	if b.Bytes < 1000 || q.Bytes() < 1000 {
		t.Errorf("учёт байт после Pop: batch=%d queue=%d", b.Bytes, q.Bytes())
	}
	// единственный батч больше лимита не выбрасывается
	q2 := NewQueueBytes(1000, 100, st)
	q2.Push([]any{big(5000)})
	if q2.Rows() != 1 {
		t.Error("единственный батч выброшен по байтам")
	}
}

func TestTransportErrorRequeuesBounded(t *testing.T) {
	m := &mockCH{down: true}
	w, st := newTestWriter(m)
	w.Attempts = 3
	batch := []any{ev("a"), ev("b")}
	w.Write(context.Background(), batch)
	if m.calls != 3 {
		t.Errorf("попыток %d, want 3", m.calls)
	}
	if st.Requeued.Load() != 1 || st.Retries.Load() != 2 {
		t.Errorf("requeued=%d retries=%d", st.Requeued.Load(), st.Retries.Load())
	}
	if w.Queue.Rows() != 2 {
		t.Fatalf("батч должен вернуться в pending: rows=%d", w.Queue.Rows())
	}
	// база поднялась — следующий проход писателя вставляет
	m.mu.Lock()
	m.down = false
	m.mu.Unlock()
	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()
	w.Queue.Close()
	<-done
	if m.rows() != 2 {
		t.Fatalf("после восстановления вставлено %d", m.rows())
	}
}

func TestQueueDropsOldest(t *testing.T) {
	st := &Stats{}
	q := NewQueue(5, st)
	q.Push([]any{1, 2})
	q.Push([]any{3, 4})
	q.Push([]any{5, 6}) // 6 > 5 → выбросить самый старый
	if q.Rows() != 4 || st.PendingDropped.Load() != 2 {
		t.Fatalf("rows=%d dropped=%d", q.Rows(), st.PendingDropped.Load())
	}
	if b, ok := q.Pop(); !ok || len(b.Rows) != 2 || b.Rows[0] != 3 {
		t.Fatalf("первый батч должен быть {3,4}: %v", b)
	}
	q.Requeue(Batch{Rows: []any{9}, Attempts: 2})
	if b, ok := q.Pop(); !ok || len(b.Rows) != 1 || b.Rows[0] != 9 || b.Attempts != 2 {
		t.Fatalf("requeue должен вставать в голову и хранить attempts: %+v", b)
	}
	// один огромный батч больше лимита не выбрасывается (иначе потеряем всё)
	q2 := NewQueue(2, st)
	q2.Push([]any{1, 2, 3})
	if q2.Rows() != 3 {
		t.Error("единственный батч выброшен")
	}
	q2.Close()
	if _, ok := q2.Pop(); !ok {
		t.Error("после Close остаток отдаётся")
	}
	if _, ok := q2.Pop(); ok {
		t.Error("после Close и опустошения Pop должен вернуть ok=false")
	}
}

func TestShortStripsQuotedRow(t *testing.T) {
	msg := "clickhouse events: HTTP 400 code 27: Code: 27. DB::Exception: Cannot parse input: expected ',' before: 'SECRET user@x.io': (at row 3)"
	if got := short(msg); strings.Contains(got, "SECRET") || !strings.Contains(got, "Cannot parse input") {
		t.Errorf("short(%q) = %q", msg, got)
	}
	if got := short(strings.Repeat("x", 1000)); len(got) > 310 {
		t.Errorf("не обрезано: %d", len(got))
	}
}

func TestParseErrorAndIsPermanent(t *testing.T) {
	e := parseError("events", 400, "", "Code: 117. DB::Exception: Incorrect data")
	if e.Code != 117 || !IsPermanent(e) {
		t.Errorf("code=%d permanent=%v", e.Code, IsPermanent(e))
	}
	e = parseError("events", 500, "241", "Code: 241. DB::Exception: Memory limit exceeded")
	if e.Code != 241 || IsPermanent(e) || !IsDivisible(e) {
		t.Errorf("memory limit — делимая: code=%d permanent=%v divisible=%v", e.Code, IsPermanent(e), IsDivisible(e))
	}
	for _, code := range []int{131, 321, 349, 69, 70} {
		if !IsDivisible(&Error{Table: "events", Status: 500, Code: code}) {
			t.Errorf("code %d должен быть divisible", code)
		}
	}
	if !IsDivisible(parseError("events", 400, "", "Bad request")) {
		t.Error("HTTP 4xx без кода — divisible")
	}
	if IsDivisible(parseError("events", 500, "", "Internal")) || IsDivisible(parseError("events", 404, "60", "")) || IsDivisible(errors.New("dial")) {
		t.Error("5xx без кода, unknown table и транспорт — не divisible")
	}
	if IsDivisible(parseError("events", 400, "27", "Cannot parse")) {
		t.Error("permanent не должен быть одновременно divisible")
	}
	e = parseError("events", 400, "", "Cannot parse DateTime64 from string")
	if !IsPermanent(e) {
		t.Error("«Cannot parse» без кода должен быть permanent")
	}
	if IsPermanent(errors.New("dial tcp: connection refused")) {
		t.Error("транспортная ошибка не permanent")
	}
	if !IsUnknownTable(parseError("ingest_rejects", 404, "60", "")) {
		t.Error("code 60 — unknown table")
	}
}

// Шторм ядовитых строк: бисекция ограничена bisectBudget вставками событий, отказы —
// одним INSERT; ни одна строка не теряется молча.
func TestBisectBudgetBoundsPoisonStorm(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	batch := make([]any, 0, 500)
	for i := 0; i < 500; i++ {
		batch = append(batch, ev("poison"))
	}
	// Один WriteBatch: не больше Attempts целых вставок плюс общий бюджет бисекции;
	// в отказы — только строки, отвергнутые поодиночке, одним INSERT; непроверенный
	// остаток возвращён в очередь, а не в ingest_rejects.
	w.Write(context.Background(), batch)
	if limit := w.Attempts + bisectBudget; m.calls > limit {
		t.Errorf("InsertEvents вызван %d раз, потолок %d", m.calls, limit)
	}
	first := len(m.rejects)
	if m.rejectCalls != 1 || first == 0 || first >= 500 || st.DeadLetter.Load() != uint64(first) {
		t.Errorf("rejectCalls=%d rejects=%d dead=%d", m.rejectCalls, first, st.DeadLetter.Load())
	}
	if got := w.Queue.Rows(); got != 500-first {
		t.Errorf("в очереди %d строк, ждали %d", got, 500-first)
	}
	// Следующие проходы дорешивают остаток: в итоге все 500 — отказы, ни одна не потеряна.
	w.Queue.Close()
	for b, ok := w.Queue.Pop(); ok; b, ok = w.Queue.Pop() {
		w.WriteBatch(context.Background(), b)
	}
	if len(m.rejects) != 500 || st.Inserted.Load() != 0 {
		t.Errorf("rejects=%d inserted=%d", len(m.rejects), st.Inserted.Load())
	}
}
