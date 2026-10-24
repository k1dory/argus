-- Реагирование: журнал автоблокировок/симуляций и настройки из консоли.
CREATE TABLE IF NOT EXISTS argus.response_log
(
    ts          DateTime DEFAULT now(),
    incident_id String,
    rule_id     LowCardinality(String),
    ip          String,
    mode        LowCardinality(String),   -- ids | simulate | ips | manual
    executor    LowCardinality(String),   -- wazuh.active-response | ngfw.usergate | …
    dry_run     UInt8,
    ok          UInt8,
    detail      String,
    reason      String,
    actor       String                    -- argus-engine | имя оператора
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (ts, incident_id)
TTL ts + INTERVAL 365 DAY;

-- Настройки, переключаемые из консоли (respond_mode и т.п.): последняя версия побеждает.
CREATE TABLE IF NOT EXISTS argus.console_settings
(
    key        String,
    value      String,
    updated_at DateTime DEFAULT now(),
    updated_by String
)
ENGINE = ReplacingMergeTree(updated_at)
ORDER BY key;
