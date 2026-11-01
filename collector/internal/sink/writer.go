package sink

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Stats — счётчики писателя для /metrics.
type Stats struct {
	Inserted       atomic.Uint64 // строк вставлено
	DeadLetter     atomic.Uint64 // строк отброшено как ядовитые
	Retries        atomic.Uint64 // повторов вставки (транспорт)
	Requeued       atomic.Uint64 // батчей возвращено в pending после N неудач
	PendingDropped atomic.Uint64 // строк выброшено из pending при переполнении
	RejectsFailed  atomic.Uint64 // строк, которые не удалось записать в ingest_rejects
}

// MaxRequeues — сколько раз подряд батч может вернуться в pending по
// транспортной ошибке при живом ClickHouse (другие батчи проходят), прежде
// чем целиком уйти в ingest_rejects. Пока база лежит, счётчик не растёт.
const MaxRequeues = 3

// DefaultPendingBytes — потолок очереди по байтам (SINK_PENDING_BYTES).
const DefaultPendingBytes = 512 << 20

var errQueueClosed = errors.New("очередь закрыта")

// Batch — элемент очереди: строки, приближённый размер в байтах и число
// возвратов в pending. mark — Stats.Inserted на момент постановки: если к
// следующему отказу счётчик вырос, база жива и отказ — на совести батча.
type Batch struct {
	Rows     []any
	Bytes    int
	Count    int
	Attempts int
	mark     uint64
	file     string
	diskSize int64
	loadErr  error
}

// Queue — ограниченная очередь батчей между батчером и писателями. При
// переполнении (по строкам или по байтам) выбрасывает самые старые батчи:
// пока ClickHouse лежит, память коллектора не растёт бесконечно, а приём не
// останавливается. Pop блокируется до батча или Close — отмена контекста
// писателей очередь не трогает, иначе финальный батч при остановке терялся.
type Queue struct {
	mu       sync.Mutex
	cond     *sync.Cond
	items    []Batch
	rows     int
	bytes    int
	maxRows  int
	maxBytes int
	closed   bool
	stats    *Stats
	spool    *diskSpool
}

func NewQueue(maxRows int, st *Stats) *Queue {
	return NewQueueBytes(maxRows, 0, st)
}

// NewQueueBytes — очередь с двумя потолками: по строкам и по байтам (0 — по умолчанию).
func NewQueueBytes(maxRows, maxBytes int, st *Stats) *Queue {
	if maxRows <= 0 {
		maxRows = 200_000
	}
	if maxBytes <= 0 {
		maxBytes = DefaultPendingBytes
	}
	q := &Queue{maxRows: maxRows, maxBytes: maxBytes, stats: st}
	q.cond = sync.NewCond(&q.mu)
	return q
}

// SizeOf — приближённый размер батча в байтах.
func SizeOf(rows []any) int {
	n := 0
	for _, r := range rows {
		switch e := r.(type) {
		case model.Event:
			n += e.ApproxSize()
		case *model.Event:
			if e != nil {
				n += e.ApproxSize()
			}
		default:
			n += 64
		}
	}
	return n
}

// Push кладёт батч в конец; лишнее — с головы (самое старое).
func (q *Queue) Push(rows []any) error {
	return q.PushContext(context.Background(), rows)
}

func (q *Queue) PushContext(ctx context.Context, rows []any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	b := Batch{Rows: rows, Bytes: SizeOf(rows), Count: len(rows), mark: q.stats.Inserted.Load()}
	if q.spool != nil {
		var err error
		b, err = q.persist(ctx, b)
		if err != nil {
			return err
		}
	}
	q.mu.Lock()
	err := ctx.Err()
	if q.closed {
		err = errQueueClosed
	}
	if err != nil {
		q.mu.Unlock()
		// A batch rejected by the producer must not be replayed after restart.
		return errors.Join(err, q.ack(b))
	}
	defer q.mu.Unlock()
	q.items = append(q.items, b)
	q.add(b, 1)
	if q.spool == nil {
		q.evict()
	}
	q.cond.Signal()
	return nil
}

// Requeue возвращает батч в голову: он самый старый, его же первым и выбросят.
func (q *Queue) Requeue(b Batch) {
	if len(b.Rows) == 0 && b.file == "" {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append([]Batch{b}, q.items...)
	q.add(b, 1)
	if q.spool == nil {
		q.evict()
	}
	q.cond.Signal()
}

func (q *Queue) add(b Batch, sign int) {
	count := b.Count
	if count == 0 {
		count = len(b.Rows)
	}
	q.rows += sign * count
	q.bytes += sign * b.Bytes
}

func (q *Queue) evict() {
	for (q.rows > q.maxRows || q.bytes > q.maxBytes) && len(q.items) > 1 {
		old := q.items[0]
		q.items = q.items[1:]
		q.add(old, -1)
		q.stats.PendingDropped.Add(uint64(len(old.Rows)))
		slog.Error("pending переполнен, старый батч выброшен", "rows", len(old.Rows), "bytes", old.Bytes,
			"pending_rows", q.rows, "pending_bytes", q.bytes)
	}
}

// Pop блокируется до появления батча; ok=false — очередь закрыта и пуста.
func (q *Queue) Pop() (Batch, bool) {
	q.mu.Lock()
	for len(q.items) == 0 {
		if q.closed {
			q.mu.Unlock()
			return Batch{}, false
		}
		q.cond.Wait()
	}
	b := q.items[0]
	q.items = q.items[1:]
	q.add(b, -1)
	q.mu.Unlock()
	if b.file != "" {
		b.Rows, b.loadErr = readSpoolBatch(b.file)
	}
	return b, true
}

// Close: Pop отдаёт остаток и затем ok=false.
func (q *Queue) Close() {
	q.mu.Lock()
	q.closed = true
	q.cond.Broadcast()
	q.mu.Unlock()
}

func (q *Queue) Rows() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.rows
}

func (q *Queue) Bytes() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

// Writer вставляет батчи с повторами и бисекцией. Транспортная ошибка —
// backoff до Attempts раз, потом батч возвращается в очередь (там его
// выбросят первым, если очередь переполнится); после MaxRequeues возвратов
// при живой базе — целиком в ingest_rejects. Ошибка данных (permanent или
// divisible) — бисекция до строк в пределах bisectBudget: в ingest_rejects одним
// INSERT уходят только строки, отвергнутые поодиночке, остальное повторяется.
type Writer struct {
	Ins        Inserter
	Queue      *Queue
	Stats      *Stats
	Attempts   int           // повторов при транспортной ошибке до Requeue (5)
	Backoff    time.Duration // первый интервал (1s), удваивается
	MaxBackoff time.Duration // потолок (30s)
	Sleep      func(ctx context.Context, d time.Duration) bool
}

func NewWriter(ins Inserter, q *Queue, st *Stats) *Writer {
	return &Writer{Ins: ins, Queue: q, Stats: st, Attempts: 5, Backoff: time.Second, MaxBackoff: 30 * time.Second}
}

// Run — цикл одного писателя. Завершается только когда очередь закрыта и
// пуста: ctx прерывает лишь ожидания backoff, чтобы при остановке не висеть.
func (w *Writer) Run(ctx context.Context) {
	for {
		b, ok := w.Queue.Pop()
		if !ok {
			return
		}
		if b.loadErr != nil {
			slog.Error("spool: не удалось прочитать батч", "err", b.loadErr, "file", b.file)
			w.Queue.Requeue(b)
			if ctx.Err() != nil && w.Queue.spool != nil {
				return
			}
			w.sleep(ctx, time.Second)
			continue
		}
		w.WriteBatch(ctx, b)
		if ctx.Err() != nil && w.Queue.spool != nil {
			return
		} // оставшиеся файлы восстановятся после перезапуска
	}
}

// Write — вставка свежего батча (для тестов и разовых вызовов).
func (w *Writer) Write(ctx context.Context, rows []any) {
	w.WriteBatch(ctx, Batch{Rows: rows, Bytes: SizeOf(rows), mark: w.Stats.Inserted.Load()})
}

// WriteBatch вставляет один батч по стратегии; ctx — на ожидания, вставка сама
// по себе не отменяется, чтобы при остановке успеть дописать.
func (w *Writer) WriteBatch(ctx context.Context, b Batch) {
	if b.file != "" {
		w.writeDurable(ctx, b)
		return
	}
	rows := b.Rows
	delay := w.Backoff
	budget := bisectBudget // один на весь WriteBatch, повторы его не пополняют
	for attempt := 1; ; attempt++ {
		err := w.insert(rows)
		if err == nil {
			return
		}
		if isData(err) {
			// Бисекция до строк; нерешённый остаток (транспорт, исчерпанный бюджет)
			// повторяется этим же циклом — с общим счётчиком попыток и паузой.
			rest, terr := w.resolve(ctx, rows, err, false, &budget)
			if len(rest) == 0 {
				return
			}
			if len(rest) < len(rows) {
				// Прогресс: часть решена, счёт возвратов при живой базе начинается
				// заново — иначе большой батч, который бисекция разбирает за
				// несколько проходов, ушёл бы в ingest_rejects после MaxRequeues.
				b.Attempts, b.mark = 0, w.Stats.Inserted.Load()
			}
			rows, b.Rows, b.Bytes, b.Count = rest, rest, SizeOf(rest), len(rest)
			if terr != nil {
				err = terr
			}
		}
		if ctx.Err() != nil {
			slog.Error("остановка: батч не вставлен", "rows", len(rows), "err", short(err.Error()))
			return
		}
		if attempt >= w.Attempts {
			w.requeue(ctx, b, delay, err)
			return
		}
		w.Stats.Retries.Add(1)
		slog.Warn("insert failed, retry", "err", short(err.Error()), "in", delay, "attempt", attempt)
		if !w.sleep(ctx, delay) {
			slog.Error("остановка: батч не вставлен", "rows", len(rows))
			return
		}
		if delay < w.MaxBackoff {
			delay *= 2
		}
	}
}

// В дисковой очереди файл подтверждается (удаляется) только когда решена судьба всех
// строк. Ошибка данных — та же бисекция до строк, что и в памяти: корректные строки
// вставляются, ядовитые уходят в ingest_rejects. Если часть осталась нерешённой
// (транспорт, остановка, ingest_rejects недоступна), spool-файл атомарно заменяется
// только этими строками: вставленные при повторе не задвоятся.
func (w *Writer) writeDurable(ctx context.Context, b Batch) {
	delay := w.Backoff
	budget := bisectBudget
	for attempt := 1; ; attempt++ {
		err := w.insert(b.Rows)
		if err == nil {
			if err := w.Queue.ack(b); err != nil {
				slog.Error("spool ack", "err", err, "file", b.file)
			}
			return
		}
		if isData(err) {
			rest, _ := w.resolve(ctx, b.Rows, err, true, &budget)
			if len(rest) == 0 {
				if err := w.Queue.ack(b); err != nil {
					slog.Error("spool ack", "err", err, "file", b.file)
				}
				return
			}
			if len(rest) < len(b.Rows) {
				nb, serr := w.Queue.shrink(b, rest)
				if serr != nil {
					// Файл остаётся целиком: при повторе вставленные строки задвоятся,
					// но ни одна не потеряется.
					slog.Error("spool: остаток батча не сохранён, файл повторится целиком", "rows", len(rest), "err", serr)
				} else {
					b = nb
				}
			}
			break
		}
		if attempt >= w.Attempts || ctx.Err() != nil {
			break
		}
		w.Stats.Retries.Add(1)
		if !w.sleep(ctx, delay) {
			break
		}
		if delay < w.MaxBackoff {
			delay *= 2
		}
	}
	b.Rows = nil
	w.Stats.Requeued.Add(1)
	w.Queue.Requeue(b)
	w.sleep(ctx, delay)
}

// requeue возвращает батч в pending, если база лежит для всех; если с момента
// постановки другие батчи прошли — отказ на совести батча, считаем попытки.
func (w *Writer) requeue(ctx context.Context, b Batch, delay time.Duration, err error) {
	inserted := w.Stats.Inserted.Load()
	if inserted != b.mark {
		b.Attempts++
	}
	b.mark = inserted
	if b.Attempts >= MaxRequeues {
		slog.Error("insert: батч отвергнут транспортом при живом ClickHouse, целиком в ingest_rejects",
			"rows", len(b.Rows), "requeues", b.Attempts, "err", short(err.Error()))
		w.deadLetter(b.Rows, err)
		return
	}
	w.Stats.Requeued.Add(1)
	slog.Warn("insert: ClickHouse недоступен, батч возвращён в pending", "rows", len(b.Rows), "requeues", b.Attempts, "err", short(err.Error()))
	w.Queue.Requeue(b)
	w.sleep(ctx, delay) // не крутить очередь вхолостую, пока база лежит
}

// insert — одна попытка; успех сразу учитывается в Stats.Inserted.
func (w *Writer) insert(rows []any) error {
	if err := w.Ins.InsertEvents(context.Background(), rows); err != nil {
		return err
	}
	w.Stats.Inserted.Add(uint64(len(rows)))
	slog.Debug("flushed", "rows", len(rows))
	return nil
}

func isData(err error) bool { return IsPermanent(err) || IsDivisible(err) }

func (w *Writer) sleep(ctx context.Context, d time.Duration) bool {
	if w.Sleep != nil {
		return w.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// bisectBudget — потолок вставок событий на бисекцию в одном WriteBatch (общий для
// всех его попыток). Без него шторм ядовитых строк (500 из 500) стоил бы ~1000 INSERT.
// Бюджет ограничивает работу за проход, а не решает судьбу данных: непроверенный к его
// исчерпанию остаток не отказ, а нерешённые строки — они повторяются с backoff, как
// при транспортной ошибке, и остаются в очереди или spool.
const bisectBudget = 128

// errBisectBudget — причина повтора остатка, до которого бисекция не дошла.
var errBisectBudget = errors.New("бюджет бисекции исчерпан, остаток не проверен")

// resolve — бисекция ошибки данных до отдельных строк: прошедшая часть вставлена,
// отвергнутая как данные (241 и др. по размеру, 27/6/53/117 по содержимому) делится
// дальше. Отказ — только строка, отвергнутая одиночным INSERT; отказы копятся и
// пишутся в ingest_rejects одним INSERT. Возвращает нерешённые строки — части с
// транспортной ошибкой, непроверенные при исчерпанном budget, остаток при остановке,
// а при keepUnrejected — и отказы, которые не удалось записать, — и последнюю причину.
func (w *Writer) resolve(ctx context.Context, rows []any, err error, keepUnrejected bool, budget *int) ([]any, error) {
	var rejects []any
	var terr error
	var split func(rows []any) []any
	split = func(rows []any) []any {
		if ctx.Err() != nil {
			return rows
		}
		mid := len(rows) / 2
		var rest []any
		for _, part := range [][]any{rows[:mid], rows[mid:]} {
			if *budget <= 0 {
				if terr == nil {
					terr = errBisectBudget
				}
				rest = append(rest, part...)
				continue
			}
			*budget--
			switch perr := w.insert(part); {
			case perr == nil:
			case isData(perr) && len(part) == 1:
				rejects = append(rejects, part...)
			case isData(perr):
				rest = append(rest, split(part)...)
			default:
				terr = perr
				rest = append(rest, part...)
			}
		}
		return rest
	}
	var rest []any
	if len(rows) == 1 {
		rejects = rows // одиночный INSERT уже отвергнут как данные
	} else {
		slog.Warn("insert: ошибка данных, делю батч", "rows", len(rows), "budget", *budget, "err", short(err.Error()))
		rest = split(rows)
	}
	if len(rejects) > 0 && !w.deadLetter(rejects, err) && keepUnrejected {
		rest = append(rest, rejects...)
	}
	return rest, terr
}

// deadLetter пишет строки в ingest_rejects одним INSERT.
func (w *Writer) deadLetter(rows []any, err error) bool {
	w.Stats.DeadLetter.Add(uint64(len(rows)))
	rejs := make([]Reject, 0, len(rows))
	ts, reason := model.FormatTS(time.Now()), full(err)
	total := 0
	for _, row := range rows {
		rej := Reject{TS: ts, Source: "unknown", Reason: reason}
		if e, ok := row.(model.Event); ok {
			rej.Source = e.Source
		} else if e, ok := row.(*model.Event); ok && e != nil {
			rej.Source = e.Source
		}
		if raw, jerr := json.Marshal(row); jerr == nil {
			rej.Raw = string(raw)
		} else {
			rej.Raw = jerr.Error()
		}
		if len(rej.Raw) > 256<<10 {
			rej.Raw = rej.Raw[:256<<10]
		}
		total += len(rej.Raw)
		// сырое событие — только на debug; на error — источник, причина и размер
		slog.Debug("dead letter raw", "source", rej.Source, "raw", rej.Raw)
		rejs = append(rejs, rej)
	}
	slog.Error("dead letter: строки отброшены", "rows", len(rejs), "source", rejs[0].Source, "reason", short(err.Error()), "bytes", total)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if ierr := w.Ins.InsertRejects(ctx, rejs); ierr != nil {
		w.Stats.RejectsFailed.Add(uint64(len(rejs)))
		if IsUnknownTable(ierr) {
			slog.Debug("ingest_rejects: таблицы нет (миграция 0011)", "err", short(ierr.Error()))
		} else {
			slog.Warn("ingest_rejects: не записано", "rows", len(rejs), "err", short(ierr.Error()))
		}
		return false
	}
	return true
}

// short — текст ошибки для лога: ClickHouse цитирует в нём кусок строки
// («…before: '<данные>'»), а сырые события в stdout на info/warn не пишем;
// цитата отрезается, остаток — до 300 символов. В ingest_rejects идёт полный.
func short(s string) string {
	for _, marker := range []string{" before: ", "(at row ", ": (while reading"} {
		if i := strings.Index(s, marker); i > 0 {
			s = s[:i] + "…"
			break
		}
	}
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}

// full — полный текст ошибки для таблицы отказов, с потолком (с текстом ClickHouse).
func full(err error) string {
	s := err.Error()
	var ce *Error
	if errors.As(err, &ce) {
		s = ce.Detail()
	}
	if len(s) > 4<<10 {
		return s[:4<<10] + "…"
	}
	return s
}
