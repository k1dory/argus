-- Лицензионный учёт (пиковый EPS за 30 дней) считался по collector_health —
-- ReplacingMergeTree ORDER BY source, которая после merge оставляет одну
-- строку на источник. Пишем heartbeat ещё и в append-only лог с TTL.
CREATE TABLE IF NOT EXISTS argus.collector_health_log
(
    source     String,
    listener   LowCardinality(String),
    seen_at    DateTime,
    events_1m  UInt32
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(seen_at)
ORDER BY (source, seen_at)
TTL seen_at + INTERVAL 90 DAY;

-- Материализованное представление: коллектор пишет только в collector_health.
CREATE MATERIALIZED VIEW IF NOT EXISTS argus.collector_health_to_log
TO argus.collector_health_log
AS SELECT source, listener, seen_at, events_1m FROM argus.collector_health;
