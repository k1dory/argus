package sink

import (
	"context"
	"testing"
	"time"

	"github.com/devitex-soft/argus/collector/internal/model"
)

// Бисекция в дисковой очереди: решённое (вставленное и отвергнутое) не повторяется,
// нерешённый транспортом остаток остаётся в spool — файл атомарно заменён остатком.
func TestWriteDurableKeepsOnlyUnresolvedRowsInSpool(t *testing.T) {
	st := &Stats{}
	m := &mockCH{}
	q, err := NewDurableQueue(t.TempDir(), 1<<20, st)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Push([]any{ev("poison"), ev("fine"), ev("timeout"), ev("fine2")}); err != nil {
		t.Fatal(err)
	}
	b, ok := q.Pop()
	if !ok || b.file == "" {
		t.Fatalf("batch not on disk: ok=%v file=%q", ok, b.file)
	}
	w := NewWriter(m, q, st)
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	w.WriteBatch(context.Background(), b)

	if st.DeadLetter.Load() != 1 || len(m.rejects) != 1 {
		t.Errorf("poison row: dead=%d rejects=%d", st.DeadLetter.Load(), len(m.rejects))
	}
	var inserted []string
	for _, rows := range m.inserted {
		for _, r := range rows {
			inserted = append(inserted, r.(model.Event).Object)
		}
	}
	if len(inserted) != 1 || inserted[0] != "fine" {
		t.Errorf("inserted %v, want only fine", inserted)
	}
	rest, ok := q.Pop()
	if !ok {
		t.Fatal("unresolved remainder was not requeued")
	}
	rows, err := readSpoolBatch(rest.file)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("spool must hold only the 2 unresolved rows, got %d", len(rows))
	}
	if q.SpoolBytes() <= 0 {
		t.Error("spool accounting lost the remainder")
	}
}
