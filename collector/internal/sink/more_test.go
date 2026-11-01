package sink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

type capturedReq struct {
	query, body, auth string
}

func captureCH(t *testing.T, status int, hdrCode, respBody string) (*ClickHouse, func() []capturedReq) {
	t.Helper()
	var mu sync.Mutex
	var reqs []capturedReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u, p, _ := r.BasicAuth()
		mu.Lock()
		reqs = append(reqs, capturedReq{query: r.URL.Query().Get("query"), body: string(b), auth: u + ":" + p})
		mu.Unlock()
		if hdrCode != "" {
			w.Header().Set("X-ClickHouse-Exception-Code", hdrCode)
		}
		w.WriteHeader(status)
		fmt.Fprint(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/", "argus", "writer", "pw"), func() []capturedReq { mu.Lock(); defer mu.Unlock(); return append([]capturedReq(nil), reqs...) }
}

// InsertRejects и InsertHealth — свои таблицы, JSONEachRow, async_insert,
// basic-auth; пустой список не ходит в сеть.
func TestInsertRejectsAndHealthRequests(t *testing.T) {
	ch, got := captureCH(t, 200, "", "")
	ctx := context.Background()
	if err := ch.InsertRejects(ctx, nil); err != nil || len(got()) != 0 {
		t.Fatalf("пустой список отказов: err=%v reqs=%d", err, len(got()))
	}
	if err := ch.InsertRejects(ctx, []Reject{{TS: "2026-01-01 00:00:00.000", Source: "ngfw", Reason: "Code: 27", Raw: `{"x":1}`}}); err != nil {
		t.Fatal(err)
	}
	if err := ch.InsertHealth(ctx, []HealthRow{{Source: "ngfw", Listener: "udp", SeenAt: "2026-01-01 00:00:00", Events1m: 3}, {Source: "k8s", Listener: "http", SeenAt: "2026-01-01 00:00:00"}}); err != nil {
		t.Fatal(err)
	}
	reqs := got()
	if len(reqs) != 2 {
		t.Fatalf("запросов: %d", len(reqs))
	}
	if !strings.Contains(reqs[0].query, "INSERT INTO argus.ingest_rejects FORMAT JSONEachRow") || !strings.Contains(reqs[0].body, `"reason":"Code: 27"`) || reqs[0].auth != "writer:pw" {
		t.Errorf("ingest_rejects: %+v", reqs[0])
	}
	if !strings.Contains(reqs[1].query, "INSERT INTO argus.collector_health FORMAT JSONEachRow") || strings.Count(reqs[1].body, "\n") != 2 || !strings.Contains(reqs[1].body, `"events_1m":3`) {
		t.Errorf("collector_health: %+v", reqs[1])
	}
}

func TestInsertErrorShapes(t *testing.T) {
	ctx := context.Background()
	// не 200 с кодом в заголовке — Error с кодом и таблицей
	ch, _ := captureCH(t, 500, "241", "Code: 241. DB::Exception: Memory limit exceeded")
	err := ch.InsertHealth(ctx, []HealthRow{{Source: "x"}})
	var ce *Error
	if !errors.As(err, &ce) || ce.Code != 241 || ce.Status != 500 || ce.Table != "collector_health" || !IsDivisible(err) {
		t.Errorf("ошибка с кодом в заголовке: %v", err)
	}
	// 200 с кодом исключения в заголовке
	ch, _ = captureCH(t, 200, "60", "")
	if err := ch.InsertRejects(ctx, []Reject{{Source: "x"}}); !IsUnknownTable(err) {
		t.Errorf("код 60 в заголовке при 200: %v", err)
	}
	// ответ больше 4 КБ при 200 — подозрительный, ошибка транспорта
	ch, _ = captureCH(t, 200, "", strings.Repeat("x", 5<<10))
	if err := ch.InsertEvents(ctx, []any{ev("a")}); err == nil || !strings.Contains(err.Error(), "oversized") || isData(err) {
		t.Errorf("слишком длинный ответ: %v", err)
	}
	// несериализуемая строка — ядовитая, а не транспорт
	ch, got := captureCH(t, 200, "", "")
	err = ch.InsertEvents(ctx, []any{make(chan int)})
	if !IsPermanent(err) || len(got()) != 0 {
		t.Errorf("несериализуемая строка: %v, запросов %d", err, len(got()))
	}
	// недоступный сервер — транспорт
	if err := New("http://127.0.0.1:1", "argus", "", "").InsertEvents(ctx, []any{ev("a")}); err == nil || isData(err) {
		t.Errorf("недоступный сервер: %v", err)
	}
	// отменённый контекст — ошибка запроса
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := ch.InsertEvents(cctx, []any{ev("a")}); err == nil {
		t.Error("отменённый контекст должен дать ошибку")
	}
}

func TestQueueDefaultsSizeOfAndSpoolCapacity(t *testing.T) {
	st := &Stats{}
	q := NewQueueBytes(0, 0, st)
	if q.maxRows != 200_000 || q.maxBytes != DefaultPendingBytes {
		t.Errorf("умолчания очереди: %d %d", q.maxRows, q.maxBytes)
	}
	if q.SpoolBytes() != 0 || q.SpoolCapacityBytes() != 0 {
		t.Error("у очереди в памяти нет spool")
	}
	e := ev("x")
	if n := SizeOf([]any{"строка", (*model.Event)(nil), &e, e}); n != 64+2*e.ApproxSize() {
		t.Errorf("SizeOf: %d", n)
	}
	q.Requeue(Batch{})
	if q.Rows() != 0 {
		t.Error("пустой батч не возвращается в очередь")
	}
	dq, err := NewDurableQueue(t.TempDir(), 4096, st)
	if err != nil {
		t.Fatal(err)
	}
	if dq.SpoolCapacityBytes() != 4096 || dq.SpoolBytes() != 0 {
		t.Errorf("ёмкость spool: %d/%d", dq.SpoolBytes(), dq.SpoolCapacityBytes())
	}
}

func TestDurableQueueOpenErrors(t *testing.T) {
	st := &Stats{}
	if _, err := NewDurableQueue("", 1, st); err == nil {
		t.Error("пустой путь")
	}
	if _, err := NewDurableQueue(t.TempDir(), 0, st); err == nil {
		t.Error("нулевой лимит")
	}
	file := filepath.Join(t.TempDir(), "file")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := NewDurableQueue(file, 1, st); err == nil {
		t.Error("путь — файл, не каталог")
	}
	// незавершённый tmp удаляется, битый батч — ошибка открытия
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".batch-abc.tmp"), []byte("partial"), 0o600)
	q, err := NewDurableQueue(dir, 1<<20, st)
	if err != nil || q.Rows() != 0 {
		t.Fatalf("tmp должен быть убран: %v rows=%d", err, q.Rows())
	}
	if _, err := os.Stat(filepath.Join(dir, ".batch-abc.tmp")); !os.IsNotExist(err) {
		t.Error("tmp не удалён")
	}
	for name, body := range map[string]string{"0001-aa.json": "garbage", "0002-bb.json": "[]"} {
		d := t.TempDir()
		os.WriteFile(filepath.Join(d, name), []byte(body), 0o600)
		if _, err := NewDurableQueue(d, 1<<20, st); err == nil || !strings.Contains(err.Error(), "spool "+name) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := syncDir(filepath.Join(dir, "missing")); err == nil {
		t.Error("syncDir несуществующего каталога")
	}
	// ack уже удалённого файла — ошибка
	q, _ = NewDurableQueue(t.TempDir(), 1<<20, st)
	q.Push([]any{ev("a")})
	b, _ := q.Pop()
	os.Remove(b.file)
	if err := q.ack(b); err == nil {
		t.Error("ack без файла должен вернуть ошибку")
	}
}

func TestPersistErrors(t *testing.T) {
	st := &Stats{}
	q, err := NewDurableQueue(t.TempDir(), 200, st)
	if err != nil {
		t.Fatal(err)
	}
	big := make([]any, 0, 10)
	for i := 0; i < 10; i++ {
		big = append(big, ev(strings.Repeat("x", 100)))
	}
	if err := q.Push(big); err == nil || !strings.Contains(err.Error(), "больше лимита") {
		t.Errorf("батч больше spool: %v", err)
	}
	if err := q.Push([]any{make(chan int)}); err == nil {
		t.Error("несериализуемый батч должен дать ошибку")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := q.PushContext(ctx, []any{ev("a")}); !errors.Is(err, context.Canceled) {
		t.Errorf("отменённый контекст: %v", err)
	}
	if q.SpoolBytes() != 0 || q.Rows() != 0 {
		t.Errorf("после ошибок место не должно быть занято: %d/%d", q.SpoolBytes(), q.Rows())
	}
}

// Run на дисковой очереди: битый файл батча → requeue и пауза; за паузу файл
// починен → батч вставлен и подтверждён; Close завершает цикл.
func TestRunDurableRecoversFromCorruptBatchFile(t *testing.T) {
	dir := t.TempDir()
	st := &Stats{}
	q, err := NewDurableQueue(dir, 1<<20, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("good")}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 1 {
		t.Fatalf("файлов spool: %d", len(files))
	}
	valid, _ := os.ReadFile(files[0])
	os.WriteFile(files[0], []byte("{broken"), 0o600)
	m := &mockCH{}
	w := NewWriter(m, q, st)
	var slept atomic.Int32
	w.Sleep = func(ctx context.Context, d time.Duration) bool {
		slept.Add(1)
		os.WriteFile(files[0], valid, 0o600) // «администратор починил файл»
		return true
	}
	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for st.Inserted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	q.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run не завершился после Close")
	}
	if st.Inserted.Load() != 1 || slept.Load() == 0 || q.SpoolBytes() != 0 || m.rows() != 1 {
		t.Errorf("inserted=%d slept=%d spool=%d rows=%d", st.Inserted.Load(), slept.Load(), q.SpoolBytes(), m.rows())
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.json")); len(left) != 0 {
		t.Errorf("файл не подтверждён: %v", left)
	}
}

// Run с отменённым контекстом на дисковой очереди завершается после первого
// батча (успешного или битого): остаток восстановится после перезапуска.
func TestRunDurableStopsOnCancel(t *testing.T) {
	st := &Stats{}
	q, _ := NewDurableQueue(t.TempDir(), 1<<20, st)
	q.Push([]any{ev("a")})
	q.Push([]any{ev("b")})
	m := &mockCH{}
	w := NewWriter(m, q, st)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Run(ctx) // не Close — цикл должен выйти сам
	if st.Inserted.Load() != 1 || q.Rows() != 1 {
		t.Errorf("inserted=%d pending=%d", st.Inserted.Load(), q.Rows())
	}
	// битый файл при отменённом контексте: requeue и выход без паузы
	dir := t.TempDir()
	q, _ = NewDurableQueue(dir, 1<<20, st)
	q.Push([]any{ev("c")})
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	os.WriteFile(files[0], []byte("nope"), 0o600)
	w = NewWriter(m, q, st)
	w.Sleep = func(context.Context, time.Duration) bool {
		t.Error("пауза при отменённом контексте не нужна")
		return false
	}
	w.Run(ctx)
	if q.Rows() != 1 {
		t.Errorf("битый батч должен остаться в очереди: %d", q.Rows())
	}
}

// writeDurable: ошибка данных → бисекция: ядовитая строка в ingest_rejects, корректная
// вставлена, ack; если
// таблицы отказов нет — батч остаётся на диске (requeue); транспорт —
// повторы с Retries, потом requeue; отменённый контекст — requeue сразу.
func TestWriteDurableBranches(t *testing.T) {
	newQ := func(t *testing.T, st *Stats, rows ...any) (*Queue, Batch) {
		q, err := NewDurableQueue(t.TempDir(), 1<<20, st)
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Push(rows); err != nil {
			t.Fatal(err)
		}
		b, _ := q.Pop()
		return q, b
	}
	t.Run("ядовитая строка → dead letter, соседняя вставлена, ack", func(t *testing.T) {
		st := &Stats{}
		m := &mockCH{}
		q, b := newQ(t, st, ev("poison"), ev("fine"))
		w := NewWriter(m, q, st)
		w.WriteBatch(context.Background(), b)
		if st.DeadLetter.Load() != 1 || len(m.rejects) != 1 || m.rows() != 1 || q.SpoolBytes() != 0 || q.Rows() != 0 || st.Requeued.Load() != 0 {
			t.Errorf("dead=%d rejects=%d inserted=%d spool=%d pending=%d requeued=%d", st.DeadLetter.Load(), len(m.rejects), m.rows(), q.SpoolBytes(), q.Rows(), st.Requeued.Load())
		}
	})
	t.Run("нет таблицы отказов → батч остаётся на диске", func(t *testing.T) {
		st := &Stats{}
		m := &mockCH{noTable: true}
		q, b := newQ(t, st, ev("poison"))
		w := NewWriter(m, q, st)
		w.Backoff = time.Millisecond
		w.WriteBatch(context.Background(), b)
		if st.RejectsFailed.Load() != 1 || q.SpoolBytes() == 0 || q.Rows() != 1 || st.Requeued.Load() != 1 {
			t.Errorf("rejectsFailed=%d spool=%d pending=%d requeued=%d", st.RejectsFailed.Load(), q.SpoolBytes(), q.Rows(), st.Requeued.Load())
		}
	})
	t.Run("транспорт → повторы, затем requeue", func(t *testing.T) {
		st := &Stats{}
		m := &mockCH{down: true}
		q, b := newQ(t, st, ev("a"))
		w := NewWriter(m, q, st)
		w.Attempts, w.Backoff, w.MaxBackoff = 3, time.Millisecond, time.Millisecond
		var sleeps []time.Duration
		w.Sleep = func(_ context.Context, d time.Duration) bool { sleeps = append(sleeps, d); return true }
		w.WriteBatch(context.Background(), b)
		if st.Retries.Load() != 2 || st.Requeued.Load() != 1 || q.Rows() != 1 || len(sleeps) != 3 {
			t.Errorf("retries=%d requeued=%d pending=%d sleeps=%v", st.Retries.Load(), st.Requeued.Load(), q.Rows(), sleeps)
		}
		if m.calls != 3 {
			t.Errorf("попыток вставки: %d", m.calls)
		}
	})
	t.Run("пауза прервана остановкой → requeue", func(t *testing.T) {
		st := &Stats{}
		m := &mockCH{down: true}
		q, b := newQ(t, st, ev("a"))
		w := NewWriter(m, q, st)
		w.Attempts = 5
		w.Sleep = func(context.Context, time.Duration) bool { return false }
		w.WriteBatch(context.Background(), b)
		if st.Retries.Load() != 1 || st.Requeued.Load() != 1 || q.Rows() != 1 || m.calls != 1 {
			t.Errorf("retries=%d requeued=%d pending=%d calls=%d", st.Retries.Load(), st.Requeued.Load(), q.Rows(), m.calls)
		}
	})
	t.Run("отменённый контекст → без повторов", func(t *testing.T) {
		st := &Stats{}
		m := &mockCH{down: true}
		q, b := newQ(t, st, ev("a"))
		w := NewWriter(m, q, st)
		w.Sleep = func(context.Context, time.Duration) bool { return false }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		w.WriteBatch(ctx, b)
		if m.calls != 1 || st.Retries.Load() != 0 || q.Rows() != 1 {
			t.Errorf("calls=%d retries=%d pending=%d", m.calls, st.Retries.Load(), q.Rows())
		}
	})
}

// Транспортная ошибка внутри бисекции: ядовитая половина — в ingest_rejects,
// «тайм-аутная» — в обычный цикл повторов и обратно в очередь.
func TestBisectHalfTransportGoesToRetryLoop(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	w.Attempts = 1
	w.Write(context.Background(), []any{ev("poison"), ev("timeout")})
	if st.DeadLetter.Load() != 1 || len(m.rejects) != 1 || m.rejects[0].Raw == "" || !strings.Contains(m.rejects[0].Raw, "poison") {
		t.Errorf("dead=%d rejects=%+v", st.DeadLetter.Load(), m.rejects)
	}
	if st.Requeued.Load() != 1 || w.Queue.Rows() != 1 {
		t.Errorf("тайм-аутная половина должна вернуться в очередь: requeued=%d pending=%d", st.Requeued.Load(), w.Queue.Rows())
	}
	b, _ := w.Queue.Pop()
	if len(b.Rows) != 1 || b.Rows[0].(model.Event).Object != "timeout" {
		t.Errorf("в очереди не та половина: %+v", b.Rows)
	}
}

// WriteBatch в памяти: остановка во время транспортной ошибки — батч не
// повторяется и не возвращается (лог), очередь не трогается.
func TestWriteBatchStopsOnCanceledContext(t *testing.T) {
	m := &mockCH{down: true}
	w, st := newTestWriter(m)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w.Write(ctx, []any{ev("a")})
	if m.calls != 1 || st.Retries.Load() != 0 || st.Requeued.Load() != 0 || w.Queue.Rows() != 0 {
		t.Errorf("calls=%d retries=%d requeued=%d pending=%d", m.calls, st.Retries.Load(), st.Requeued.Load(), w.Queue.Rows())
	}
	// пауза прервана остановкой — тоже без requeue
	m = &mockCH{down: true}
	w, st = newTestWriter(m)
	w.Sleep = func(context.Context, time.Duration) bool { return false }
	w.Write(context.Background(), []any{ev("a")})
	if m.calls != 1 || st.Retries.Load() != 1 || w.Queue.Rows() != 0 {
		t.Errorf("calls=%d retries=%d pending=%d", m.calls, st.Retries.Load(), w.Queue.Rows())
	}
}

func TestDeadLetterReasonCappedAndRawPreserved(t *testing.T) {
	m := &mockCH{}
	w, st := newTestWriter(m)
	longErr := errors.New(strings.Repeat("ё", 3<<10))
	e := ev("x")
	if !w.deadLetter([]any{e, &e, "не событие"}, longErr) {
		t.Fatal("deadLetter должен записать отказы")
	}
	if st.DeadLetter.Load() != 3 || len(m.rejects) != 3 {
		t.Fatalf("dead=%d rejects=%d", st.DeadLetter.Load(), len(m.rejects))
	}
	if !strings.HasSuffix(m.rejects[0].Reason, "…") || len(m.rejects[0].Reason) != 4<<10+len("…") {
		t.Errorf("причина не обрезана до 4 КБ: %d", len(m.rejects[0].Reason))
	}
	if m.rejects[0].Source != "test" || m.rejects[1].Source != "test" || m.rejects[2].Source != "unknown" {
		t.Errorf("источники отказов: %q %q %q", m.rejects[0].Source, m.rejects[1].Source, m.rejects[2].Source)
	}
	if m.rejects[2].Raw != `"не событие"` {
		t.Errorf("raw произвольной строки: %q", m.rejects[2].Raw)
	}
	if full(errors.New("short")) != "short" {
		t.Error("короткая причина без обрезки")
	}
}
