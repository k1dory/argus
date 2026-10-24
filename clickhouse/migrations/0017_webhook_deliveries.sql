-- Отметки исходящих вебхуков движка: дедуп «один инцидент — одна задача»
-- переживает перезапуск. state = created — промежуточный шаг цели сделан
-- (задача создана, исполнитель ещё не назначен), ref — id задачи;
-- state = delivered — доставка завершена. Последняя версия — по updated_at.
CREATE TABLE IF NOT EXISTS argus.webhook_deliveries
(
    target      LowCardinality(String),
    dedup_key   String,
    incident_id String,
    event       LowCardinality(String),
    state       LowCardinality(String),
    ref         String,
    updated_at  DateTime64(3, 'UTC')
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY (target, dedup_key)
TTL toDateTime(updated_at) + INTERVAL 180 DAY;
