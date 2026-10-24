package sink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
		b := Batch{file: path, diskSize: info.Size(), Count: len(rows), Bytes: SizeOf(rows)}
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
		q.mu.Unlock()
		if free {
			break
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

func (q *Queue) ack(b Batch) error {
	if b.file == "" {
		return nil
	}
	if err := os.Remove(b.file); err != nil {
		return err
	}
	q.mu.Lock()
	q.spool.used -= b.diskSize
	q.mu.Unlock()
	return syncDir(q.spool.dir)
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
