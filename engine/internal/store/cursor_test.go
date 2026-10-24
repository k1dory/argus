package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devitex-soft/argus/engine/internal/model"
)

func row(sec int, hash uint64) eventRow {
	t := time.Date(2026, 10, 20, 10, 0, sec, 0, time.UTC)
	return eventRow{Event: &model.Event{TS: model.FormatTS(t), Action: fmt.Sprintf("a%d", hash), ReceivedAt: t}, ReceivedAt: t, Hash: hash}
}

// later — «сейчас» заведомо позже всех секунд тестовых строк: все устоялись.
var later = time.Date(2026, 10, 20, 11, 0, 0, 0, time.UTC)

func hashes(evs []*model.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return out
}

// Курсор читает последнюю секунду включительно и не отдаёт одну строку дважды;
// вставка той же секунды после опроса попадает в следующую выборку.
func TestAdvanceCursorSameSecondLateInsert(t *testing.T) {
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	evs, next := advanceCursor(cur, []eventRow{row(0, 1), row(1, 10), row(1, 11)}, 1000, later)
	if len(evs) != 3 || !next.At.Equal(row(1, 0).ReceivedAt) || len(next.Seen) != 2 || next.Hash != 0 {
		t.Fatalf("первая выборка: %v, cursor %+v", hashes(evs), next)
	}
	// Повторное чтение той же секунды с новой строкой 12: отдаётся только она.
	evs, next2 := advanceCursor(next, []eventRow{row(1, 10), row(1, 11), row(1, 12)}, 1000, later)
	if len(evs) != 1 || evs[0].Action != "a12" || len(next2.Seen) != 3 || !next2.At.Equal(next.At) {
		t.Fatalf("поздняя вставка той же секунды: %v, cursor %+v", hashes(evs), next2)
	}
	// Ничего нового — курсор не меняется.
	evs, next3 := advanceCursor(next2, nil, 1000, later)
	if len(evs) != 0 || len(next3.Seen) != 3 {
		t.Fatalf("пустая выборка: %+v", next3)
	}
	// Новая секунда: Seen начинается заново.
	evs, next4 := advanceCursor(next3, []eventRow{row(1, 10), row(1, 11), row(1, 12), row(2, 20)}, 1000, later)
	if len(evs) != 1 || evs[0].Action != "a20" || len(next4.Seen) != 1 || !next4.At.Equal(row(2, 0).ReceivedAt) {
		t.Fatalf("следующая секунда: %v, cursor %+v", hashes(evs), next4)
	}
}

// LIMIT посреди секунды: её строки откладываются, курсор встаёт на её начало —
// остаток секунды не теряется.
func TestAdvanceCursorLimitDefersLastSecond(t *testing.T) {
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	evs, next := advanceCursor(cur, []eventRow{row(0, 1), row(0, 2), row(1, 10), row(1, 11)}, 4, later)
	if len(evs) != 2 || hashes(evs)[1] != "a2" || !next.At.Equal(row(1, 0).ReceivedAt) || len(next.Seen) != 0 || next.Hash != 0 || !next.More {
		t.Fatalf("усечённая выборка: %v, cursor %+v", hashes(evs), next)
	}
	evs, next = advanceCursor(next, []eventRow{row(1, 10), row(1, 11), row(1, 12)}, 4, later)
	if len(evs) != 3 || len(next.Seen) != 3 {
		t.Fatalf("дочитывание секунды: %v, cursor %+v", hashes(evs), next)
	}
}

// Больше LIMIT строк в одной секунде: продолжение по хешу, без зацикливания.
func TestAdvanceCursorBurstWithinSecond(t *testing.T) {
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 1, 0, time.UTC))
	evs, next := advanceCursor(cur, []eventRow{row(1, 10), row(1, 11), row(1, 12)}, 3, later)
	if len(evs) != 3 || next.Hash != 12 || len(next.Seen) != 3 || !next.More {
		t.Fatalf("шторм: %v, cursor %+v", hashes(evs), next)
	}
	// Следующий запрос начинается с hash >= 12: строка 12 уже отдана, 13 и 14 — новые.
	evs, next = advanceCursor(next, []eventRow{row(1, 12), row(1, 13), row(1, 14)}, 3, later)
	if len(evs) != 2 || hashes(evs)[0] != "a13" || next.Hash != 14 {
		t.Fatalf("продолжение: %v, cursor %+v", hashes(evs), next)
	}
	// Секунда дочитана (меньше LIMIT): продолжение по хешу сбрасывается.
	evs, next = advanceCursor(next, []eventRow{row(1, 14), row(2, 1)}, 3, later)
	if len(evs) != 1 || next.Hash != 0 || !next.At.Equal(row(2, 0).ReceivedAt) || next.More {
		t.Fatalf("конец шторма: %v, cursor %+v", hashes(evs), next)
	}
}

// После шторма внутри секунды (LIMIT внутри неё) неполная страница сбрасывает
// Hash: следующий опрос перечитывает секунду с начала и по Seen отдаёт только
// позднюю вставку с меньшим хешем.
func TestAdvanceCursorRereadsSecondAfterBurst(t *testing.T) {
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 1, 0, time.UTC))
	_, next := advanceCursor(cur, []eventRow{row(1, 10), row(1, 11)}, 2, later) // страница полная → продолжение по хешу
	if next.Hash != 11 || !next.More {
		t.Fatalf("продолжение: %+v", next)
	}
	_, next = advanceCursor(next, []eventRow{row(1, 11), row(1, 12)}, 3, later) // неполная → секунда дочитана в этом опросе
	if next.Hash != 0 || next.More || len(next.Seen) != 3 {
		t.Fatalf("конец страниц: %+v", next)
	}
	// Следующий опрос: вся секунда с начала, появилась строка с хешем 5 (меньше всех ранее виденных).
	evs, next := advanceCursor(next, []eventRow{row(1, 5), row(1, 10), row(1, 11), row(1, 12)}, 1000, later)
	if len(evs) != 1 || evs[0].Action != "a5" || len(next.Seen) != 4 {
		t.Fatalf("поздняя вставка с меньшим хешем: %v, cursor %+v", hashes(evs), next)
	}
}

// Неустоявшиеся секунды (моложе now − cursorSettle) откладываются: их хвост
// может быть ещё не виден.
func TestAdvanceCursorSettle(t *testing.T) {
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	now := time.Date(2026, 10, 20, 10, 0, 5, 500000000, time.UTC) // устоялись секунды ≤ 10:00:02
	evs, next := advanceCursor(cur, []eventRow{row(0, 1), row(2, 2), row(3, 3), row(5, 5)}, 2, now)
	if len(evs) != 2 || hashes(evs)[1] != "a2" || !next.At.Equal(row(2, 0).ReceivedAt) || next.More {
		t.Fatalf("устоявшиеся секунды: %v, cursor %+v", hashes(evs), next)
	}
	evs, next2 := advanceCursor(cur, []eventRow{row(4, 4), row(5, 5)}, 1000, now)
	if len(evs) != 0 || !next2.At.Equal(cur.At) {
		t.Fatalf("только свежие строки — курсор стоит: %v, %+v", hashes(evs), next2)
	}
}

// Хеш строки покрывает все колонки схемы, attrs — по отсортированным ключам.
func TestRowHashCoversAllColumns(t *testing.T) {
	for _, col := range []string{"attrs", "value", "unit", "bytes", "packets", "session_id", "pii", "severity", "actor_kind", "proto", "source_class", "raw"} {
		if !strings.Contains(rowHashExpr, col) {
			t.Errorf("хеш строки не учитывает %s", col)
		}
	}
	if !strings.Contains(rowHashExpr, "arraySort(mapKeys(attrs))") {
		t.Error("attrs должны хешироваться детерминированно")
	}
}

// Запрос: включительная секунда с хешем, порядок received_at + хеш, хеш в
// выборке; ответ разбирается в события с ReceivedAt.
func TestEventsSinceQueryAndParse(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b) + " " + r.URL.RawQuery
		_, _ = w.Write([]byte(`{"ts":"2026-10-20 10:00:01.000","source":"s","action":"x","attrs":{},"received_str":"2026-10-20 10:00:01","row_hash":18446744073709551615}` + "\n"))
	}))
	defer srv.Close()
	c := New(srv.URL, "argus", "", "")
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 1, 0, time.UTC))
	cur.Hash = 7
	evs, next, err := c.EventsSince(context.Background(), cur, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"received_at > {cursor:DateTime} OR (received_at = {cursor:DateTime} AND cityHash64(", ">= {hash:UInt64}", "ORDER BY received_at, row_hash", "param_hash=7", "param_cursor=2026-10-20+10%3A00%3A01"} {
		if !strings.Contains(got, want) {
			t.Errorf("нет %q в запросе: %s", want, got)
		}
	}
	if len(evs) != 1 || evs[0].ReceivedAt != cur.At || next.Hash != 0 {
		t.Fatalf("events %v cursor %+v", evs, next)
	}
	if _, ok := next.Seen[18446744073709551615]; !ok {
		t.Fatalf("uint64 хеш должен читаться без потери точности: %+v", next.Seen)
	}
}
