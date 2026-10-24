-- Почасовой агрегат по правилам: дешёвые long-range запросы для дашбордов.
CREATE TABLE IF NOT EXISTS argus.wazuh_alerts_hourly
(
    hour             DateTime('UTC'),
    rule_id          UInt32,
    rule_level       UInt8,
    -- Описание функционально зависит от rule_id: держим его вне ключа,
    -- чтобы дрейф текста правила не раздваивал строки агрегата.
    rule_description SimpleAggregateFunction(any, String),
    agent_name       LowCardinality(String),
    cnt              UInt64
)
ENGINE = SummingMergeTree(cnt)
ORDER BY (hour, rule_id, rule_level, agent_name)
TTL hour + INTERVAL 730 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS argus.mv_wazuh_alerts_hourly
TO argus.wazuh_alerts_hourly
AS SELECT
    toStartOfHour(timestamp) AS hour,
    rule_id,
    rule_level,
    rule_description,
    agent_name,
    toUInt64(1) AS cnt
FROM argus.wazuh_alerts;
