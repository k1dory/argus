CREATE DATABASE IF NOT EXISTS argus;

-- Алерты Wazuh, разложенные шиппером (wazuh-shipper) из alerts.json.
-- Полный исходный JSON сохраняется в колонке raw.
CREATE TABLE IF NOT EXISTS argus.wazuh_alerts
(
    timestamp        DateTime64(3, 'UTC'),
    alert_id         String,
    agent_id         LowCardinality(String),
    agent_name       LowCardinality(String),
    agent_ip         String,
    manager_name     LowCardinality(String),
    rule_id          UInt32,
    rule_level       UInt8,
    rule_description String,
    rule_groups      Array(LowCardinality(String)),
    rule_firedtimes  UInt32,
    mitre_ids        Array(String),
    mitre_tactics    Array(LowCardinality(String)),
    mitre_techniques Array(String),
    decoder_name     LowCardinality(String),
    location         String,
    srcip            String,
    full_log         String CODEC(ZSTD(3)),
    raw              String CODEC(ZSTD(3)),
    ingested_at      DateTime DEFAULT now()
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp, rule_level, agent_id)
TTL toDateTime(timestamp) + INTERVAL 180 DAY;

-- Вердикты Policy-as-Code от policyd (OPA/Rego).
CREATE TABLE IF NOT EXISTS argus.policy_verdicts
(
    evaluated_at DateTime('UTC'),
    entity_type  LowCardinality(String),  -- agent | sca
    entity_id    String,
    entity_name  String,
    policy       LowCardinality(String),  -- wazuh/agent | wazuh/sca
    compliant    UInt8,
    violations   Array(String)
)
ENGINE = MergeTree
ORDER BY (evaluated_at, policy, entity_id)
TTL evaluated_at + INTERVAL 90 DAY;
