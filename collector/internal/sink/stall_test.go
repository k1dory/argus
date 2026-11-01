package sink

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// Полумёртвый ClickHouse: 241 на группу, таймаут 159 на каждую строку. Батч
// возвращается без прогресса — отметка застревания с первого такого прохода,
// возраст растёт, пока батч стоит; прогресс или запись её снимают.
func TestStallMarkTracksBatchWithoutProgress(t *testing.T) {
	for _, durable := range []bool{false, true} {
		t.Run(fmt.Sprintf("durable=%t", durable), func(t *testing.T) {
			st := &Stats{}
			q := NewQueue(1000, st)
			if durable {
				var err error
				if q, err = NewDurableQueue(t.TempDir(), 1<<20, st); err != nil {
					t.Fatal(err)
				}
			}
			rows := make([]any, 8)
			for i := range rows {
				rows[i] = ev(fmt.Sprintf("row-%d", i))
			}
			if err := q.Push(rows); err != nil {
				t.Fatal(err)
			}
			healthy := false
			ins := pr43ReviewRetryInserter{
				events: func(part []any) error {
					if healthy {
						return nil
					}
					if len(part) > 1 {
						return &Error{Table: "events", Status: 500, Code: 241}
					}
					return &Error{Table: "events", Status: 500, Code: 159}
				},
				rejects: func([]Reject) error { return nil },
			}
			w := NewWriter(ins, q, st)
			w.Attempts = 1
			w.Sleep = func(context.Context, time.Duration) bool { return true }
			t0 := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
			clock := t0
			w.Now = func() time.Time { return clock }

			pass := func() {
				t.Helper()
				b, ok := q.Pop()
				if !ok || b.loadErr != nil {
					t.Fatalf("pop: ok=%t err=%v", ok, b.loadErr)
				}
				w.WriteBatch(context.Background(), b)
			}
			if q.StuckFor(t0) != 0 {
				t.Fatal("пустая очередь не может стоять")
			}
			pass()
			if st.StalledPasses.Load() != 1 || q.StuckFor(t0.Add(time.Minute)) != time.Minute {
				t.Fatalf("первый проход без прогресса: passes=%d stuck=%v", st.StalledPasses.Load(), q.StuckFor(t0.Add(time.Minute)))
			}
			clock = t0.Add(5 * time.Minute)
			pass()
			// Отсчёт — от первого прохода без прогресса, а не от последнего.
			if got := q.StuckFor(t0.Add(11 * time.Minute)); got != 11*time.Minute {
				t.Fatalf("возраст застревания: %v", got)
			}
			healthy = true
			pass()
			if got := q.StuckFor(t0.Add(12 * time.Minute)); got != 0 || st.Inserted.Load() != 8 {
				t.Fatalf("после записи: stuck=%v inserted=%d", got, st.Inserted.Load())
			}
		})
	}
}

// Проход, который хоть что-то записал, застреванием не считается: отметка
// снимается, хотя остаток (строка с таймаутом) вернулся в очередь.
func TestStallMarkClearedByProgress(t *testing.T) {
	st := &Stats{}
	q := NewQueue(1000, st)
	if err := q.Push([]any{ev("poison"), ev("ok-1"), ev("ok-2"), ev("timeout")}); err != nil {
		t.Fatal(err)
	}
	w := NewWriter(&mockCH{}, q, st)
	w.Attempts = 1
	w.Sleep = func(context.Context, time.Duration) bool { return true }
	b, _ := q.Pop()
	q.noteStall(&b, time.Now().Add(-time.Hour))
	w.WriteBatch(context.Background(), b)
	if st.Inserted.Load() == 0 || q.Rows() == 0 {
		t.Fatalf("фикстура: часть строк записана, остаток в очереди: inserted=%d pending=%d", st.Inserted.Load(), q.Rows())
	}
	if got := q.StuckFor(time.Now()); got != 0 {
		t.Fatalf("прогресс должен снять отметку: %v", got)
	}
}
