-- 0011: dead-letter коллектора и статус вердикта политики.
-- Идемпотентно: IF NOT EXISTS везде, повторный прогон ничего не ломает.

-- Отклонённые записи приёма (не разобрались, не прошли схему, превысили лимит):
-- коллектор кладёт сюда сырьё с причиной, чтобы источник не терялся молча.
CREATE TABLE IF NOT EXISTS argus.ingest_rejects
(
    ts     DateTime64(3, 'UTC'),
    source LowCardinality(String),
    reason String,
    raw    String CODEC(ZSTD(3))
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, source)
TTL toDateTime(ts) + INTERVAL 30 DAY;

-- Вердикты policyd получают статус (pass | fail | unknown), чтобы отличать
-- «не соответствует» (fail) от «не смогли проверить» (unknown: ошибка API,
-- таймаут раунда, ошибка eval). '' — строки, записанные до этой миграции.
ALTER TABLE argus.policy_verdicts ADD COLUMN IF NOT EXISTS status LowCardinality(String) DEFAULT '';

-- Вердикт аналитика: причина, показанная оператору (почему уверенность/профиль
-- такие; пусто — вердикт полный).
ALTER TABLE argus.incident_verdicts ADD COLUMN IF NOT EXISTS shown_reason String DEFAULT '';
