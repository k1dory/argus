package sink

import "time"

// Застревание батча. Бисекция ограничена бюджетом, и при полумёртвом
// ClickHouse (241 на группу, таймаут на каждую строку) батч может возвращаться
// в очередь без прогресса бесконечно: данные целы, но не идут. Выбирать строки
// хитрее не нужно — нужно, чтобы это заметил оператор. Батч без прогресса за
// проход получает отметку с моментом первого такого прохода; очередь отдаёт
// возраст самой старой отметки (метрика и событие collector.sink_stalled).
// Отметка общая у копий батча (указатель) и живёт только в памяти: после
// рестарта отсчёт начинается заново.

type stallMark struct{ since time.Time }

// noteStall — проход без прогресса: отметить батч (если ещё не отмечен).
func (q *Queue) noteStall(b *Batch, now time.Time) {
	q.stats.StalledPasses.Add(1)
	if b.stall == nil {
		b.stall = &stallMark{since: now}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.stalls == nil {
		q.stalls = map[*stallMark]bool{}
	}
	q.stalls[b.stall] = true
}

// clearStall — батч продвинулся, записан или выброшен: отметка снимается.
func (q *Queue) clearStall(b *Batch) {
	if b.stall == nil {
		return
	}
	q.mu.Lock()
	delete(q.stalls, b.stall)
	q.mu.Unlock()
	b.stall = nil
}

// StuckFor — сколько самый старый батч в очереди не продвигается (0 — таких нет).
// Батч, поднятый из spool при старте, отметки ещё не имеет (она в памяти), но и
// прогресса у него не было: пока он не записан и не сокращён, он считается
// стоящим с момента старта — иначе нулевой возраст до первого прохода выглядел бы
// восстановлением.
func (q *Queue) StuckFor(now time.Time) time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	var oldest time.Time
	if q.restoredPending > 0 {
		oldest = q.startedAt
		if d := now.Sub(oldest); d <= 0 {
			return time.Nanosecond
		}
	}
	for m := range q.stalls {
		if oldest.IsZero() || m.since.Before(oldest) {
			oldest = m.since
		}
	}
	if oldest.IsZero() {
		return 0
	}
	return now.Sub(oldest)
}
