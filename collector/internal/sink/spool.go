package sink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// diskSpool хранит подтверждённые батчи до успешной вставки в ClickHouse
// (или в ingest_rejects). После аварийного завершения файлы читаются снова:
// возможна повторная вставка последнего батча, поэтому семантика — at least once.
type diskSpool struct {
	dir      string
	maxBytes int64
	used     int64
}

// NewDurableQueue открывает очередь на постоянном томе. В отличие от очереди
// в памяти, она никогда не вытесняет старые батчи при заполнении: PushContext
// ждёт освобождения места или отмены контекста.
func NewDurableQueue(dir string, maxBytes int64, st *Stats) (*Queue, error) {
	if dir == "" || maxBytes <= 0 {
		return nil, errors.New("нужны путь и положительный лимит дисковой очереди")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	q := NewQueueBytes(1, 1, st) // ограничения памяти в дисковом режиме не применяются
	q.spool = &diskSpool{dir: dir, maxBytes: maxBytes}
	q.startedAt = time.Now()
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".batch-") && strings.HasSuffix(e.Name(), ".tmp") && !e.IsDir() {
			// Временный файл не был подтверждён: после сбоя его можно удалить.
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasSuffix(e.Name(), ".json") && !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		rows, err := readSpoolBatch(path)
		if err != nil {
			return nil, fmt.Errorf("spool %s: %w", name, err)
		}
		b := Batch{file: path, diskSize: info.Size(), Count: len(rows), Bytes: SizeOf(rows), restored: true}
		q.restoredPending++
		q.items = append(q.items, b)
		q.add(b, 1)
		q.spool.used += info.Size()
	}
	return q, nil
}

func readSpoolBatch(path string) ([]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []model.Event
	if err := json.Unmarshal(raw, &events); err != nil {
		return nil, err
	}
	if len(events) == 0 {
		return nil, errors.New("пустой батч")
	}
	rows := make([]any, len(events))
	for i := range events {
		rows[i] = events[i]
	}
	return rows, nil
}

func (q *Queue) persist(ctx context.Context, b Batch) (Batch, error) {
	data, err := json.Marshal(b.Rows)
	if err != nil {
		return b, err
	}
	need := int64(len(data))
	if need > q.spool.maxBytes {
		return b, fmt.Errorf("батч %d байт больше лимита spool %d", need, q.spool.maxBytes)
	}
	for {
		if err := ctx.Err(); err != nil {
			return b, err
		}
		q.mu.Lock()
		if q.closed {
			q.mu.Unlock()
			return b, errQueueClosed
		}
		free := q.spool.used+need <= q.spool.maxBytes
		if free {
			q.spool.used += need
		}
		debt := len(q.ackDebt) > 0
		q.mu.Unlock()
		if free {
			break
		}
		if debt {
			// Место может держать долг подтверждения: писатели ждут в Pop нового
			// батча, а он ждёт места — повтор удаления здесь разрывает этот круг.
			q.retryAcks() // проверка места — на следующем круге, после паузы ниже
		}
		select {
		case <-ctx.Done():
			return b, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	rollback := func(err error) (Batch, error) {
		q.mu.Lock()
		q.spool.used -= need
		q.mu.Unlock()
		return b, err
	}
	f, err := os.CreateTemp(q.spool.dir, ".batch-*.tmp")
	if err != nil {
		return rollback(err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return rollback(err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return rollback(err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return rollback(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return rollback(err)
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		_ = os.Remove(f.Name())
		return rollback(err)
	}
	path := filepath.Join(q.spool.dir, fmt.Sprintf("%020d-%s.json", time.Now().UnixNano(), hex.EncodeToString(nonce[:])))
	if err := os.Rename(f.Name(), path); err != nil {
		_ = os.Remove(f.Name())
		return rollback(err)
	}
	if err := syncDir(q.spool.dir); err != nil {
		_ = os.Remove(path)
		return rollback(err)
	}
	b.file, b.diskSize, b.Rows = path, need, nil
	return b, nil
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// shrink — атомарно заменить spool-файл батча остатком rows (temp + rename поверх
// того же пути): сбой до rename оставляет прежний файл, после — только остаток.
// Батч возвращается без строк (перечитается из файла), учёт места — по новому размеру.
func (q *Queue) shrink(b Batch, rows []any) (Batch, error) {
	if b.file == "" {
		b.Rows = rows
		b.Bytes, b.Count = SizeOf(rows), len(rows)
		return b, nil
	}
	data, err := json.Marshal(rows)
	if err != nil {
		return b, err
	}
	f, err := os.CreateTemp(q.spool.dir, ".batch-*.tmp")
	if err != nil {
		return b, err
	}
	tmp := f.Name()
	fail := func(err error) (Batch, error) {
		_ = f.Close()
		_ = os.Remove(tmp)
		return b, err
	}
	if err := f.Chmod(0600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return b, err
	}
	if err := os.Rename(tmp, b.file); err != nil {
		_ = os.Remove(tmp)
		return b, err
	}
	// После rename на диске уже остаток: учёт и метаданные — по нему, даже если fsync
	// каталога не удался (иначе место осталось бы занятым размером прежнего файла).
	if err := syncDir(q.spool.dir); err != nil {
		slog.Warn("spool: fsync каталога после замены остатком не удался", "err", err, "file", b.file)
	}
	need := int64(len(data))
	q.mu.Lock()
	q.spool.used += need - b.diskSize
	if b.restored {
		q.restoredPending-- // остаток сохранён меньшим — у батча был прогресс
		b.restored = false
	}
	q.mu.Unlock()
	b.diskSize, b.Rows = need, nil
	b.Bytes, b.Count = SizeOf(rows), len(rows)
	return b, nil
}

func (q *Queue) ack(b Batch) error {
	if b.file == "" {
		return nil
	}
	if err := os.Remove(b.file); err != nil {
		// Данные уже в ClickHouse, а файл не удалился (EACCES, EROFS, каталог
		// недоступен): долг подтверждения. retryAcks удалит файл позже, и тогда же
		// батч перестанет держать учёт места и стартовую отметку застревания.
		q.mu.Lock()
		q.ackDebt = append(q.ackDebt, Batch{file: b.file, diskSize: b.diskSize, restored: b.restored})
		start := !q.ackRetrying
		q.ackRetrying = true
		q.mu.Unlock()
		if start {
			go q.ackRetryLoop()
		}
		return err
	}
	q.settleAck(b)
	return syncDir(q.spool.dir)
}

func (q *Queue) settleAck(b Batch) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.spool.used -= b.diskSize
	if b.restored {
		q.restoredPending--
	}
}

// ackRetryLoop — повтор удаления по таймеру, пока долг не погашен или очередь не
// закрыта: на простаивающей очереди (писатели ждут в Pop) больше некому его
// вызвать, а долг держит место и стартовую отметку застревания.
func (q *Queue) ackRetryLoop() {
	t := time.NewTicker(ackRetryEvery)
	defer t.Stop()
	for range t.C {
		q.retryAcks()
		q.mu.Lock()
		done := len(q.ackDebt) == 0 || q.closed
		if done {
			q.ackRetrying = false
		}
		q.mu.Unlock()
		if done {
			return
		}
	}
}

// ackRetryEvery — период повтора удаления при долге подтверждения.
const ackRetryEvery = time.Second

// retryAcks — повторить удаление файлов батчей, записанных в ClickHouse, но не
// подтверждённых (ack не удалил файл). Файла нет при доступном каталоге — его уже
// нет, долг погашен. Зовётся писателем перед каждым батчем.
func (q *Queue) retryAcks() {
	if q.spool == nil {
		return
	}
	q.mu.Lock()
	debt := q.ackDebt
	q.ackDebt = nil
	q.mu.Unlock()
	if len(debt) == 0 {
		return
	}
	var left []Batch
	settled := false
	for _, b := range debt {
		err := os.Remove(b.file)
		if err != nil && errors.Is(err, os.ErrNotExist) {
			if _, derr := os.Stat(q.spool.dir); derr == nil {
				err = nil
			}
		}
		if err != nil {
			left = append(left, b)
			continue
		}
		q.settleAck(b)
		settled = true
	}
	if settled {
		if err := syncDir(q.spool.dir); err != nil {
			slog.Warn("spool: fsync каталога после отложенного подтверждения не удался", "err", err)
		}
	}
	if len(left) > 0 {
		q.mu.Lock()
		q.ackDebt = append(left, q.ackDebt...)
		q.mu.Unlock()
	}
}

func (q *Queue) SpoolBytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.spool == nil {
		return 0
	}
	return q.spool.used
}

func (q *Queue) SpoolCapacityBytes() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.spool == nil {
		return 0
	}
	return q.spool.maxBytes
}
