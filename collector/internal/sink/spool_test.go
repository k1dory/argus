package sink

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

func TestDurableQueueRecoversAndAcknowledges(t *testing.T) {
	dir := t.TempDir()
	q, err := NewDurableQueue(dir, 1<<20, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("before-crash")}); err != nil {
		t.Fatal(err)
	}
	if q.SpoolBytes() == 0 {
		t.Fatal("батч не записан на диск")
	}
	// Даже извлечённый писателем батч остаётся на диске до ack.
	if _, ok := q.Pop(); !ok {
		t.Fatal("очередь пуста")
	}
	recovered, err := NewDurableQueue(dir, 1<<20, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Rows() != 1 {
		t.Fatalf("после рестарта строк: %d", recovered.Rows())
	}
	b, ok := recovered.Pop()
	if !ok || len(b.Rows) != 1 || b.Rows[0].(model.Event).Object != "before-crash" {
		t.Fatal("батч не восстановлен")
	}
	if err := recovered.ack(b); err != nil {
		t.Fatal(err)
	}
	if recovered.SpoolBytes() != 0 {
		t.Fatal("ack не освободил место")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "" && len(e.Name()) > 5 && e.Name()[len(e.Name())-5:] == ".json" {
			t.Fatal("файл не удалён после ack")
		}
	}
}

func TestDurableQueueBackpressureAndReplay(t *testing.T) {
	dir := t.TempDir()
	q, err := NewDurableQueue(dir, 1<<20, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("one")}); err != nil {
		t.Fatal(err)
	}
	q.spool.maxBytes = q.SpoolBytes()*2 - 1
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := q.PushContext(ctx, []any{ev("two")}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ожидали backpressure, получили %v", err)
	}
	m := &mockCH{down: true}
	w := NewWriter(m, q, &Stats{})
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return false }
	b, _ := q.Pop()
	w.WriteBatch(context.Background(), b)
	if q.Rows() != 1 {
		t.Fatal("ошибка ClickHouse потеряла дисковый батч")
	}
	m.down = false
	b, _ = q.Pop()
	w.WriteBatch(context.Background(), b)
	if m.rows() != 1 || q.SpoolBytes() != 0 {
		t.Fatalf("replay: rows=%d spool=%d", m.rows(), q.SpoolBytes())
	}
}

func TestDurableQueueRequeueKeepsOtherBatches(t *testing.T) {
	q, err := NewDurableQueue(t.TempDir(), 1<<20, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		if err := q.Push([]any{ev(name)}); err != nil {
			t.Fatal(err)
		}
	}
	first, ok := q.Pop()
	if !ok {
		t.Fatal("первый батч отсутствует")
	}
	q.Requeue(first)
	if q.Rows() != 2 {
		t.Fatalf("после повтора осталось %d батчей", q.Rows())
	}
	for _, name := range []string{"one", "two"} {
		b, ok := q.Pop()
		if !ok || b.Rows[0].(model.Event).Object != name {
			t.Fatalf("потерян батч %q", name)
		}
		if err := q.ack(b); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDurableQueueRejectsClosedAndCanceledPushes(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(fmt.Sprint("closed=", closed), func(t *testing.T) {
			dir := t.TempDir()
			q, err := NewDurableQueue(dir, 1<<20, &Stats{})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if closed {
				q.Close()
			} else {
				cancel()
			}
			if err := q.PushContext(ctx, []any{ev("rejected")}); err == nil {
				t.Fatal("expected rejected push")
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(files) != 0 || q.SpoolBytes() != 0 {
				t.Fatal("rejected push left a batch to replay after restart")
			}
		})
	}
}

func TestDurableQueueCloseUnblocksFullSpool(t *testing.T) {
	q, err := NewDurableQueue(t.TempDir(), 1<<20, &Stats{})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("one")}); err != nil {
		t.Fatal(err)
	}
	q.spool.maxBytes = q.SpoolBytes()
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- q.PushContext(ctx, []any{ev("two")}) }()
	q.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("push to closed queue succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the producer")
	}
}
