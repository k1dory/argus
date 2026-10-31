package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
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

// Запрос: включительная секунда с ключом event_id, ограниченный срез received_at,
// порядок received_at + event_id; ответ разбирается в события с ReceivedAt, ключ
// uint64 — без потери точности.
func TestEventsSinceQueryAndParse(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b) + " " + r.URL.RawQuery
		_, _ = w.Write([]byte(`{"ts":"2026-10-20 10:00:01.000","source":"s","action":"x","attrs":{},"received_str":"2026-10-20 10:00:01","event_id":18446744073709551615}` + "\n"))
	}))
	defer srv.Close()
	c := New(srv.URL, "argus", "", "")
	cur := StartCursor(time.Date(2026, 10, 20, 10, 0, 1, 0, time.UTC))
	cur.Hash = 7
	evs, next, err := c.EventsSince(context.Background(), cur, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"received_at >= {cursor:DateTime} AND received_at < {upto:DateTime}", "(received_at > {cursor:DateTime} OR event_id >= {hash:UInt64})",
		"ORDER BY received_at, event_id", "param_hash=7", "param_cursor=2026-10-20+10%3A00%3A01", "param_upto=2026-10-20+10%3A05%3A01"} {
		if !strings.Contains(got, want) {
			t.Errorf("нет %q в запросе: %s", want, got)
		}
	}
	for _, bad := range []string{"cityHash64", "AS raw", "row_hash"} {
		if strings.Contains(got, bad) {
			t.Errorf("в запросе не должно быть %q: хеш считается при вставке (event_id), raw не читается: %s", bad, got)
		}
	}
	if len(evs) != 1 || evs[0].ReceivedAt != cur.At || evs[0].Raw != "" {
		t.Fatalf("events %+v", evs)
	}
	// страница упёрлась в LIMIT внутри секунды: курсор стоит, ключ продолжения — максимальный
	if !next.More || !next.At.Equal(cur.At) || next.Hash != 18446744073709551615 || next.Step != sliceDefault/2 {
		t.Fatalf("cursor %+v", next)
	}
	if _, ok := next.Seen[18446744073709551615]; !ok {
		t.Fatalf("uint64 ключ должен читаться без потери точности: %+v", next.Seen)
	}
}

// Верх среза — At+Step, но не дальше последней устоявшейся секунды; курсор на
// неустоявшейся секунде — читать нечего.
func TestSliceEnd(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	cur := StartCursor(now.Add(-time.Hour))
	if upto, ok := sliceEnd(cur, now); !ok || !upto.Equal(cur.At.Add(sliceDefault)) {
		t.Fatalf("догон: %v %v", upto, ok)
	}
	cur = StartCursor(now.Add(-time.Minute))
	if upto, ok := sliceEnd(cur, now); !ok || !upto.Equal(now.Add(-cursorSettle).Add(time.Second)) {
		t.Fatalf("у края: %v %v", upto, ok)
	}
	cur = StartCursor(now.Add(-cursorSettle).Add(time.Second))
	if _, ok := sliceEnd(cur, now); ok {
		t.Fatal("неустоявшаяся секунда — запроса нет")
	}
	cur = Cursor{At: now.Add(-time.Hour)}
	if upto, _ := sliceEnd(cur, now); !upto.Equal(cur.At.Add(sliceDefault)) {
		t.Fatalf("Step 0 — по умолчанию: %v", upto)
	}
}

// Пустой срез в прошлом сдвигает курсор на свой верх (иначе догон стоял бы на
// дыре в потоке), ширина растёт; страница по LIMIT сужает срез и не уводит
// курсор за прочитанное; у края догона More снимается; пределы ширины соблюдаются.
func TestFinishSlice(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	cur := StartCursor(now.Add(-time.Hour))
	upto := cur.At.Add(sliceDefault)
	_, adv := advanceCursor(cur, nil, 100, now)
	next := finishSlice(cur, adv, 0, 100, upto, now)
	if !next.At.Equal(upto) || !next.More || next.Step != 2*sliceDefault || len(next.Seen) != 0 {
		t.Fatalf("пустой срез: %+v", next)
	}
	rows := []eventRow{row(0, 1), row(1, 2)}
	cur = StartCursor(rows[0].ReceivedAt)
	_, adv = advanceCursor(cur, rows, 2, later)
	next = finishSlice(cur, adv, 2, 2, cur.At.Add(sliceDefault), later)
	// последняя секунда страницы могла быть прочитана не целиком — курсор встаёт на неё
	if !next.At.Equal(rows[1].ReceivedAt) || !next.More || next.Step != sliceDefault/2 {
		t.Fatalf("LIMIT: курсор внутри среза, срез уже: %+v", next)
	}
	cur.Step = sliceMin
	if next = finishSlice(cur, adv, 2, 2, cur.At.Add(sliceMin), later); next.Step != sliceMin {
		t.Fatalf("нижний предел: %v", next.Step)
	}
	cur = StartCursor(now.Add(-10 * time.Second))
	cur.Step = sliceMax
	edge := now.Add(-cursorSettle).Add(time.Second)
	_, adv = advanceCursor(cur, nil, 100, now)
	if next = finishSlice(cur, adv, 0, 100, edge, now); next.More || !next.At.Equal(edge) || next.Step != sliceMax {
		t.Fatalf("край догона и верхний предел: %+v", next)
	}
	// средняя страница (не меньше четверти LIMIT) — ширина не меняется
	if next = finishSlice(StartCursor(now.Add(-time.Hour)), adv, 50, 100, now.Add(-55*time.Minute), now); next.Step != sliceDefault {
		t.Fatalf("ширина без изменений: %v", next.Step)
	}
}

// Эмулятор SQL-границ EventsSince: фильтрует по переданным DateTime/event_id,
// сортирует и применяет LIMIT. Нужен для проверки всей цепочки, а не только
// advanceCursor: finishSlice тоже может потерять дедупликацию и поздний лог.
func cursorHTTPStore(t *testing.T, rows []eventRow) (*ClickHouse, func(eventRow)) {
	t.Helper()
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		at, err := time.Parse("2006-01-02 15:04:05", query.Get("param_cursor"))
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		upto, err := time.Parse("2006-01-02 15:04:05", query.Get("param_upto"))
		if err != nil || !upto.After(at) || upto.Sub(at) > sliceMax {
			t.Errorf("запрос обязан иметь ограниченное непустое окно: from=%v to=%v err=%v", at, upto, err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hash, _ := strconv.ParseUint(query.Get("param_hash"), 10, 64)
		limit, _ := strconv.Atoi(query.Get("param_limit"))
		mu.Lock()
		var selected []eventRow
		for _, row := range rows {
			if !row.ReceivedAt.Before(at) && row.ReceivedAt.Before(upto) && (row.ReceivedAt.After(at) || row.Hash >= hash) {
				selected = append(selected, row)
			}
		}
		mu.Unlock()
		sort.Slice(selected, func(i, j int) bool {
			if selected[i].ReceivedAt.Equal(selected[j].ReceivedAt) {
				return selected[i].Hash < selected[j].Hash
			}
			return selected[i].ReceivedAt.Before(selected[j].ReceivedAt)
		})
		if limit > 0 && len(selected) > limit {
			selected = selected[:limit]
		}
		for _, row := range selected {
			if err := json.NewEncoder(w).Encode(map[string]any{
				"ts": row.Event.TS, "action": row.Event.Action, "event_id": row.Hash,
				"received_str": row.ReceivedAt.Format("2006-01-02 15:04:05"),
			}); err != nil {
				t.Error(err)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL, "argus", "", ""), func(row eventRow) {
		mu.Lock()
		defer mu.Unlock()
		rows = append(rows, row)
	}
}

// Регрессия PR7: advanceCursor сбрасывает Hash для повторного чтения секунды,
// но finishSlice перепрыгивает через неё и очищает Seen. Проверка через
// EventsSince показывает потерю поздней строки с меньшим ключом после LIMIT.
func TestEventsSinceRereadsLastSecondAfterBurst(t *testing.T) {
	// Вставка опаздывает лишь на секунду за cursorSettle, у live-края.
	// Это контракт последней прочитанной секунды, не произвольный backfill.
	at := time.Now().UTC().Add(-cursorSettle - time.Second).Truncate(time.Second)
	makeRow := func(h uint64) eventRow {
		return eventRow{Event: &model.Event{TS: model.FormatTS(at), Action: fmt.Sprintf("raw-%d", h)}, ReceivedAt: at, Hash: h}
	}
	c, insert := cursorHTTPStore(t, []eventRow{makeRow(10), makeRow(20), makeRow(30)})
	cur := StartCursor(at)
	cur.Step = time.Hour // последний срез текущего опроса
	events, cur, err := c.EventsSince(context.Background(), cur, 3)
	if err != nil || len(events) != 3 || !cur.More {
		t.Fatalf("начальная полная страница: events=%v cursor=%+v err=%v", hashes(events), cur, err)
	}
	events, cur, err = c.EventsSince(context.Background(), cur, 3)
	if err != nil || len(events) != 0 || cur.More {
		t.Fatalf("страница дочитана; повторный граничный ключ не выдаётся: events=%v cursor=%+v err=%v", hashes(events), cur, err)
	}
	insert(makeRow(5)) // INSERT с received_at той же секунды завершился после чтения
	events, _, err = c.EventsSince(context.Background(), cur, 100)
	if err != nil || len(events) != 1 || events[0].Action != "raw-5" {
		t.Fatalf("поздняя строка с меньшим ключом потеряна после finishSlice: events=%v cursor=%+v err=%v", hashes(events), cur, err)
	}
}

// Лимит в production не меняется между опросами. После возврата к live-краю
// первая страница может целиком состоять из Seen; это не повод повторять её
// бесконечно. Проверяем публичный EventsSince, включая SQL и finishSlice.
func TestEventsSinceReplayFullSeenPageMakesProgress(t *testing.T) {
	const limit = 3
	at := time.Now().UTC().Add(-cursorSettle - time.Second).Truncate(time.Second)
	makeRow := func(at time.Time, h uint64, action string) eventRow {
		return eventRow{Event: &model.Event{TS: model.FormatTS(at), Action: action}, ReceivedAt: at, Hash: h}
	}
	c, insert := cursorHTTPStore(t, []eventRow{
		makeRow(at, 10, "first-10"), makeRow(at, 20, "first-20"), makeRow(at, 30, "first-30"),
	})
	cur := StartCursor(at)
	cur.Step = time.Hour
	seen := map[string]int{}
	finished := false
	for page := 0; page < 8; page++ {
		events, next, err := c.EventsSince(context.Background(), cur, limit)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			seen[event.Action]++
		}
		cur = next
		if !cur.More {
			finished = true
			break
		}
	}
	if !finished || len(seen) != 3 {
		t.Fatalf("первый опрос должен прочитать три строки и закончиться: seen=%v cursor=%+v", seen, cur)
	}
	// Следующая секунда уже устоялась. Курсор должен пропустить старые Seen и
	// дойти до неё с тем же LIMIT, без повторной выдачи прежних трёх событий.
	insert(makeRow(at.Add(time.Second), 40, "next-second"))
	finished = false
	for page := 0; page < 8; page++ {
		events, next, err := c.EventsSince(context.Background(), cur, limit)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			seen[event.Action]++
		}
		cur = next
		if !cur.More {
			finished = true
			break
		}
	}
	if !finished || seen["next-second"] != 1 {
		t.Fatalf("повторное чтение полной страницы Seen зациклилось: LIMIT=%d seen=%v cursor=%+v", limit, seen, cur)
	}
	for action, count := range seen {
		if count != 1 {
			t.Fatalf("дедупликация нарушена: %s отдано %d раз", action, count)
		}
	}
}

// Верх среза исключительный, низ следующего включительный. Дырки расширяют
// окно, но не должны пропускать записи на стыках или выдавать их повторно.
func TestEventsSinceEmptySlicesAndBoundaries(t *testing.T) {
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	var rows []eventRow
	for i, delta := range []time.Duration{5 * time.Minute, 5*time.Minute + time.Second, 35 * time.Minute, 95 * time.Minute} {
		at := base.Add(delta)
		rows = append(rows, eventRow{Event: &model.Event{TS: model.FormatTS(at.Add(-24 * time.Hour)), Action: fmt.Sprintf("boundary-%d", i)}, ReceivedAt: at, Hash: uint64(i + 1)})
	}
	c, _ := cursorHTTPStore(t, rows)
	cur := StartCursor(base)
	seen := map[string]int{}
	finished := false
	for page := 0; page < 32; page++ {
		events, next, err := c.EventsSince(context.Background(), cur, 100)
		if err != nil {
			t.Fatal(err)
		}
		if page == 0 && (len(events) != 0 || !next.At.Equal(base.Add(5*time.Minute))) {
			t.Fatalf("пустой первый срез должен дойти до исключённой граничной секунды: events=%v cursor=%+v", hashes(events), next)
		}
		for _, e := range events {
			seen[e.Action]++
		}
		if next.More && !next.At.After(cur.At) {
			t.Fatalf("неполная страница в прошлом обязана продвигать курсор: before=%+v after=%+v", cur, next)
		}
		cur = next
		if !cur.More {
			finished = true
			break
		}
	}
	if !finished || len(seen) != len(rows) {
		t.Fatalf("догон не завершён или граничные события потеряны: finished=%v seen=%v", finished, seen)
	}
	for _, r := range rows {
		if seen[r.Event.Action] != 1 {
			t.Fatalf("каждое событие ровно один раз: %v", seen)
		}
	}
}
